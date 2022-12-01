#ifndef RAR_ENV_H
#define RAR_ENV_H

/**
 * @brief filter some environment variables according to the whitelist
*/
int filter_env_vars(char *envp[], char *envp_filtered[], char *envp_whitelist[] );

#endif