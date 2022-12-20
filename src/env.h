#ifndef ENV_H
#define ENV_H


int filter_env_vars(char **envp, char **whitelist, char **checklist, char ***new_envp);

int secure_path(char *path, char *secure_path);

#endif