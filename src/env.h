#ifndef ENV_H
#define ENV_H

/**
 * @brief filter the environment variables according to the whitelist and the checklist
 * @param envp the environment variables to filter
 * @param whitelist the whitelist of environment variables to keep separated by a comma
 * @param checklist the checklist of environment variables to check separated by a comma
 * @param new_envp the new environment variables
*/
int filter_env_vars(char **envp, char **whitelist, char **checklist, char ***new_envp);

/**
 * @brief replace the path by a secure path
*/
int secure_path(char *path, char *secure_path);

#endif