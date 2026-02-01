//this program will is my version of ls


#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>

int main(int argc,char * argv[])
{
    char pathname[1026];
    DIR * dir;
    struct dirent * entry;
    
    if(argc > 1)
    {
      strcpy(pathname,argv[1]);
    }
    else
    {
       getcwd(pathname,sizeof(pathname));
    }
    
    dir = opendir(pathname);
    if(dir == NULL)
    {
        perror("couldn't open directory");
    }

    while((entry = readdir(dir)) != NULL)
    {   
        if(entry->d_name[0] != '.')
        {

            printf("%s   ", entry->d_name);
        }
    }
    
    closedir(dir);

    
    return 0;

}




