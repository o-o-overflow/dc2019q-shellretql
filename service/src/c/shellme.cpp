#include <phpcpp.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <linux/seccomp.h>
#include <sys/ptrace.h>
#include <linux/audit.h>
#include <sys/prctl.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <seccomp.h> /* libseccomp */

extern "C" {

   void shell_this(char* the_shell)
   {
        int len = strlen(the_shell);
        void *ptr = mmap(0, len, PROT_EXEC | PROT_WRITE | PROT_READ, MAP_ANON | MAP_PRIVATE, -1, 0);
        void (*shell)();
        scmp_filter_ctx ctx;
        int rc = 0;

	  
	     memcpy(ptr, the_shell, len);


        // Set an alarm
        alarm(30);

        ctx = seccomp_init(SCMP_ACT_KILL); // default action: kill
        printf("setting seccomps\n");
        // setup strict whitelist
        rc += seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
        rc += seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
        rc += seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
        if (rc != 0) {
            perror("seccomp_rule_add failed");
            exit(-2);
        }

        // load the filter
        seccomp_load(ctx);
        if (rc != 0) {
            perror("seccomp_load failed");
            exit(-1);
        }
        // seccomp
        //seccomp(SECCOMP_SET_MODE_STRICT, 0, NULL);
        //prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT);

        // exec
        shell = (void (*)()) ptr;
        shell();

        return;
   }
   
}

Php::Value shellme (Php::Parameters &params)
{
   std::string shell = params[0];
   char* the_shell = (char*)shell.c_str();

   shell_this(the_shell);

   return true;
}


/**
 *  tell the compiler that the get_module is a pure C function
 */
extern "C" {

    /**
     *  Function that is called by PHP right after the PHP process
     *  has started, and that returns an address of an internal PHP
     *  strucure with all the details and features of your extension
     *
     *  @return void*   a pointer to an address that is understood by PHP
     */
    PHPCPP_EXPORT void *get_module() 
    {
        // static(!) Php::Extension object that should stay in memory
        // for the entire duration of the process (that's why it's static)
        static Php::Extension myExtension("shellme", "1.0");

		myExtension.add<shellme>("shellme", {
			  Php::ByVal("shell", Php::Type::String),
		});

        // return the extension
        return myExtension;
    }
}

