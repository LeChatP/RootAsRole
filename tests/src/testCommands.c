#include "testCommands.h"

#define USER_CAP_FILE_ROOT "tests/resources/rootrole.xml"
#define USER_CAP_FILE_TEMP "tests/resources/temp.xml"

int beforeRoot(void){
    char abspath[PATH_MAX];
    realpath(USER_CAP_FILE_TEMP,abspath);
    copy_file(USER_CAP_FILE_ROOT,abspath);
    realpath(USER_CAP_FILE_ROOT,abspath);
    char *args[1] = {get_username(getuid())};
    copy_file_args(abspath,USER_CAP_FILE_ROOT,1,args);
    return 0;
}

int afterRoot(void){
    char abspath[PATH_MAX];
    realpath(USER_CAP_FILE_TEMP,abspath);
    copy_file(abspath,USER_CAP_FILE_ROOT);
    return remove(abspath);
}

/**
 * test if command with simple quote works
 */
int testQuotedCommand(void){
    int return_code = 0;
    beforeRoot();
    char *name = "-r root -c \"echo 'bobo'\"";
    int outfp;
    sr_command(name,&outfp);
    char ligne[1024];
    while (read(outfp,ligne,sizeof(ligne)) >= 0)
    {
        if(strstr(ligne,"bobo") != NULL){
            return_code = 1;
            goto free_rscs;
        }
    }
    name = "-r root -c \"echo 'bo\\'bo'\"";
    sr_command(name,&outfp);
    while (read(outfp,ligne,sizeof(ligne)) >= 0)
    {
        if(strstr(ligne,"bo'bo") != NULL){
            return_code = 1;
            goto free_rscs;
        }
    }
    free_rscs:
    afterRoot();
    return return_code;
}