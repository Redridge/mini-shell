/**
 * Operating Systems 2013 - Assignment 2
 *
 */

#include <assert.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <unistd.h>

#include "utils.h"

#define READ		0
#define WRITE		1
#define ERR			2

typedef struct pipe_data {

	int *pipefd1;
	int *pipefd0;

} pipe_data;

static char *get_word(word_t *s);
/**
 * Internal change-directory command.
 */
static bool shell_cd(word_t *dir)
{
	int ret;

	ret = chdir(get_word(dir));
	if (ret < 0)
		fprintf(stderr, "mini-shell: cd: %s not found\n",
			get_word(dir));
	return ret;
}

/**
 * Internal exit/quit command.
 */
static int shell_exit(void)
{
	_exit(0);
	return 0;
}

/*
 * Set env variable from word_t verb
 */
static int shell_setenv(word_t *verb)
{
	const char *var = verb->string;
	const char *value = verb->next_part->next_part->string;

	return setenv(var, value, 1);
}

/**
 * Concatenate parts of the word to obtain the command
 */
static char *get_word(word_t *s)
{
	int string_length = 0;
	int substring_length = 0;

	char *string = NULL;
	char *substring = NULL;

	while (s != NULL) {
		substring = strdup(s->string);

		if (substring == NULL)
			return NULL;

		if (s->expand == true) {
			char *aux = substring;

			substring = getenv(substring);

			/* prevents strlen from failing */
			if (substring == NULL)
				substring = "";

			free(aux);
		}

		substring_length = strlen(substring);

		string = realloc(string, string_length + substring_length + 1);
		if (string == NULL) {
			if (s->expand == false)
				free(substring);
			return NULL;
		}

		memset(string + string_length, 0, substring_length + 1);

		strcat(string, substring);
		string_length += substring_length;

		if (s->expand == false)
			free(substring);

		s = s->next_part;
	}

	return string;
}

/**
 * Concatenate command arguments in a NULL terminated list in order to pass
 * them directly to execv.
 */
static char **get_argv(simple_command_t *command, int *size)
{
	char **argv;
	word_t *param;

	int argc = 0;

	argv = calloc(argc + 1, sizeof(char *));
	assert(argv != NULL);

	argv[argc] = get_word(command->verb);
	assert(argv[argc] != NULL);

	argc++;

	param = command->params;
	while (param != NULL) {
		argv = realloc(argv, (argc + 1) * sizeof(char *));
		assert(argv != NULL);

		argv[argc] = get_word(param);
		assert(argv[argc] != NULL);

		param = param->next_word;
		argc++;
	}

	argv = realloc(argv, (argc + 1) * sizeof(char *));
	assert(argv != NULL);

	argv[argc] = NULL;
	*size = argc;

	return argv;
}

static int do_redirect_pipe(simple_command_t *s)
{
	pipe_data *data;
	int ret;

	data = (pipe_data *)s->aux;
	if (data->pipefd0) {
		close(data->pipefd0[1]);
		ret = dup2(data->pipefd0[0], READ);
		if (ret == -1) {
			fprintf(stderr, "Failed to dup\n");
			return ret;
		}
	}
	if (data->pipefd1) {
		close(data->pipefd1[0]);
		ret = dup2(data->pipefd1[1], WRITE);
		if (ret == -1) {
			fprintf(stderr, "Failed to dup\n");
			return ret;
		}
	}
	return 0;
}

static void do_close_pipe(pipe_data *data)
{
	if (data->pipefd0) {
		close(data->pipefd0[0]);
		close(data->pipefd0[1]);
	}
}

/*
 * Do the necessary redirections
 */
static int do_redirect(simple_command_t *s, int dup)
{
	int fd, COND_APPEND = 0;

	COND_APPEND = s->io_flags ? O_APPEND : O_TRUNC;

	if (s->out != NULL) {
		fd = open(get_word(s->out), O_CREAT | O_WRONLY | COND_APPEND,
			0644);
		if (fd < 0) {
			fprintf(stderr, "Error opening file %s\n",
				get_word(s->out));
			return -1;
		}
		if (dup)
			dup2(fd, WRITE);
		else
			close(fd);
	}
	if (s->err != NULL) {
		/* in case the &> operator is used */
		if (s->out != NULL && strcmp(get_word(s->out),
			get_word(s->err)) == 0) {
			if (dup)
				dup2(WRITE, ERR);
		} else {
			fd = open(get_word(s->err),
				O_CREAT | O_WRONLY | COND_APPEND, 0644);
			if (fd < 0) {
				fprintf(stderr, "Error opening file %s\n",
					get_word(s->err));
				return -1;
			}
			if (dup)
				dup2(fd, ERR);
			else
				close(fd);
		}
	}
	if (s->in != NULL) {
		fd = open(get_word(s->in), O_RDONLY);
		if (fd < 0) {
			fprintf(stderr, "Error opening file %s\n",
				get_word(s->in));
			return -1;
		}
		if (dup)
			dup2(fd, READ);
		else
			close(fd);
	}
	return 0;
}

/**
 * Verify and return command type
 * 0 - external
 * 1 - cd
 * 2 - exit
 * 3 - variable assignment
 */
static int get_command_type(word_t *word)
{
	char *s = get_word(word);

	if (!strcmp(s, "cd"))
		return 1;
	if (!strcmp(s, "exit"))
		return 2;
	if (!strcmp(s, "quit"))
		return 2;
	if (strchr(s, '=') != NULL)
		return 3;
	return 0;
}

/**
 * Parse a simple command (internal, environment variable assignment,
 * external command).
 */
static int parse_simple(simple_command_t *s, int level,
						command_t *father)
{
	int int_cmd, pid, status;
	/* sanity checks */
	int_cmd = get_command_type(s->verb);

	switch (int_cmd) {
	case 0:
		break;
	/* if builtin command, execute the command */
	case 1:
		do_redirect(s, 0);
		return shell_cd(s->params);
	case 2:
		return shell_exit();
	case 3:
		/* if variable assignment, execute the assignment and return
		 * the exit status
		 */
		return shell_setenv(s->verb);
	}

	/* run external command */
	pid = fork();
	if (pid == -1) {
		fprintf(stderr, "Error forking\n");
		return -1;
	}
	/* if child process */
	if (pid == 0) {
		if (s->aux)
			if (do_redirect_pipe(s) == -1)
				return -1;
		if (do_redirect(s, 1) == -1)
			return -1;
		status = execvp(get_word(s->verb), get_argv(s, &status));
		if (status == -1)
			fprintf(stderr, "Execution failed for '%s'\n",
				get_word(s->verb));
			exit(-1);
	} else {
		if (s->aux)
			do_close_pipe(s->aux);
		waitpid(pid, &status, 0);
	}
	return status;
}

/**
 * Process two commands in parallel, by creating two children.
 */
static int do_in_parallel(command_t *cmd1, command_t *cmd2, int level,
							command_t *father)
{
	int pid, pid2, status;
	/* execute cmd1 and cmd2 simultaneously */
	pid = fork();
	if (pid == -1) {
		fprintf(stderr, "Error forking\n");
		return -1;
	}
	/* if child process */
	if (pid == 0) {
		status = parse_command(cmd1, level, father);
		exit(status);
	}
	/* if a pipe is open only the child should retain it */
	if (cmd1->aux)
		do_close_pipe(cmd1->aux);
	pid2 = fork();
	if (pid2 == -1) {
		fprintf(stderr, "Error forking\n");
		return -1;
	}
	/* if child process */
	if (pid2 == 0) {
		status = parse_command(cmd2, level, father);
		exit(status);
	}
	/* if a pipe is open only the child should retain it */
	if (cmd2->aux)
		do_close_pipe(cmd2->aux);
	waitpid(pid, &status, 0);
	waitpid(pid2, &status, 0);
	return status;
}

/**
 * Run commands by creating an anonymous pipe (cmd1 | cmd2)
 */
static bool do_on_pipe(command_t *cmd1, command_t *cmd2, int level,
						command_t *father)
{
	int pipefd[2];
	pipe_data pipe1, pipe0;
	/* redirect the output of cmd1 to the input of cmd2 */
	if (pipe(pipefd) == -1) {
		fprintf(stderr, "mini-shell: can't make pipe\n");
		return -1;
	}

	pipe1.pipefd1 = pipefd;
	pipe1.pipefd0 = NULL;
	cmd1->aux = &pipe1;
	if (cmd2->aux) {
		((pipe_data *)cmd2->aux)->pipefd0 = pipefd;
	} else {
		pipe0.pipefd1 = NULL;
		pipe0.pipefd0 = pipefd;
		cmd2->aux = &pipe0;
	}

	return do_in_parallel(cmd1, cmd2, level+1, father);
}

/**
 * Parse and execute a command.
 */
int parse_command(command_t *c, int level, command_t *father)
{
	int ret;
	/* sanity checks */

	if (c->op == OP_NONE) {
		if (c->aux)
			c->scmd->aux = c->aux;
		/* execute a simple command */
		return parse_simple(c->scmd, level, father);
	}

	switch (c->op) {
	case OP_SEQUENTIAL:
		parse_command(c->cmd1, level+1, c);
		return parse_command(c->cmd2, level+1, c);

	case OP_PARALLEL:
		/* execute the commands simultaneously */
		return do_in_parallel(c->cmd1, c->cmd2, level+1, c);

	case OP_CONDITIONAL_NZERO:
		/* execute the second command only if the first one
		 * returns non zero
		 */
		ret = parse_command(c->cmd1, level+1, c);
		if (ret != 0)
			return parse_command(c->cmd2, level+1, c);
		else
			return ret;

	case OP_CONDITIONAL_ZERO:
		/* execute the second command only if the first one
		 * returns zero
		 */
		ret = parse_command(c->cmd1, level+1, c);
		if (ret == 0)
			return parse_command(c->cmd2, level+1, c);
		else
			return ret;

	case OP_PIPE:
		/* redirect the output of the first command to the
		 * input of the second
		 */
		if (c->aux)
			c->cmd2->aux = c->aux;
		return do_on_pipe(c->cmd1, c->cmd2, level+1, father);

	default:
		assert(false);
	}

	return 0;
}

/**
 * Readline from mini-shell.
 */
char *read_line()
{
	char *instr;
	char *chunk;
	char *ret;

	int instr_length;
	int chunk_length;

	int endline = 0;

	instr = NULL;
	instr_length = 0;

	chunk = calloc(CHUNK_SIZE, sizeof(char));
	if (chunk == NULL) {
		fprintf(stderr, ERR_ALLOCATION);
		return instr;
	}

	while (!endline) {
		ret = fgets(chunk, CHUNK_SIZE, stdin);
		if (ret == NULL)
			break;

		chunk_length = strlen(chunk);
		if (chunk[chunk_length - 1] == '\n') {
			chunk[chunk_length - 1] = 0;
			endline = 1;
		}

		instr = realloc(instr, instr_length + CHUNK_SIZE + 1);
		if (instr == NULL)
			break;

		memset(instr + instr_length, 0, CHUNK_SIZE);
		strcat(instr, chunk);
		instr_length += chunk_length;
	}

	free(chunk);

	return instr;
}

