#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "lib/user/syscall.h"
static void syscall_handler (struct intr_frame *);

	void
syscall_init (void) 
{
	intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

bool check_esp(struct intr_frame *f)
{
	return (!(is_user_vaddr((int *)f->esp) && (int *)f->esp != NULL
				&& pagedir_get_page(thread_current()->pagedir, (f->esp)) != NULL));
}
/*
   void put_status_in_parent(int status)
{
	struct thread *parent = thread_current()->parent;
	//struct thread *curr = thread_current();
	int child_tid = thread_current()->tid;
        struct thread *child;
        struct s_child *childs = parent->child_threads;
        int success = 0;
        int i;
        int struct_size = sizeof(struct s_child);

        for (i = 0; i < parent->child_cnt ; i++)
        {

                child = (childs + struct_size*i)->child;
                if ( child->tid == child_tid)
                {
                        if ((childs + struct_size * i)->status == NULL)
                        {
				(childs + struct_size*i)->status = status;
                                //success = 1;
                                return ;
                        }
                        else
                        {
                                printf("\nTrying to put status twice\n");
				return;
                        }
                }
        }
	printf("\nDidn't find the tid of child in parent's array\n");
	
}
*/
	static void
syscall_handler (struct intr_frame *f UNUSED) 
{

	int fd;
	const void *buf;
	unsigned int size;
	int status;
	int pid,tid;
	char *saveptr;
	char *delimiter = " ";
	char *file;


	void *old_esp = f->esp;

	if(check_esp(f))
		goto error_in_esp;


	int interrupt_number = *(int *)(f->esp);
	(f->esp) += sizeof(int);

	if(check_esp(f))
		goto error_in_esp;

	switch(interrupt_number)
	{
		case SYS_WRITE:

			fd = *(int *)(f->esp);
			(f->esp) += sizeof(int);


			if(check_esp(f)){
				goto error_in_esp;}
			buf = *(void **)(f->esp);
			(f->esp) += sizeof(void *);

			if(check_esp(f)){
				goto error_in_esp;}
			if(!(is_user_vaddr((char *)buf) && (char *)buf != NULL 
						&& pagedir_get_page(thread_current()->pagedir, buf) != NULL)) 
			{
				
				f->eax = -1;
				f->esp = old_esp;
				put_status_in_parent(f->eax);	
				struct semaphore *a = &(thread_current()->exit_sema);
				
				sema_up(&(thread_current()->exit_sema));
				
				printf ("%s: exit(%d)\n", strtok_r(thread_name(), delimiter, &saveptr), f->eax);
				thread_exit();	
			}
			size = *(unsigned int *)(f->esp);
			
			putbuf(buf, size);	

			f->esp = old_esp;
			break;
		case SYS_WAIT:
			pid = *(pid_t *)(f->esp);
			if (pid == -1 ){
				goto error_in_esp;	}
			f->eax = process_wait(pid);
//			if(f->eax == -1){
//				printf("\nHEHE``\n");
//				goto error_in_esp;}
				
			f->esp = old_esp;
			break;
		case SYS_EXEC:
			file = *(char **)(f->esp);
			
			if(!(is_user_vaddr((char *)file) && (char *)file != NULL
                                                && pagedir_get_page(thread_current()->pagedir, file) != NULL)){
			goto error_in_esp;}

			f->esp = old_esp;
			if((tid = process_execute(file)) == TID_ERROR)
			{
				pid = -1;
			}
			else
			{
				pid = tid;
			}
			f->eax = pid;

			//needs to wait till the process gets loaded !! Get some mechanism.
			break;
		case SYS_HALT:
			shutdown_power_off();	
			break;
		case SYS_EXIT:
			status = *(int *)(f->esp);
			f->eax = status;

			// put the status in the array of parent !!

		if((struct thread *)thread_current()->parent == NULL)
		{
			goto error_in_esp;
		}			
			put_status_in_parent(status);



			struct semaphore *a = &(thread_current()->exit_sema);

			f->esp = old_esp;	
			printf ("%s: exit(%d)\n", strtok_r(thread_name(), delimiter, &saveptr), f->eax);
			sema_up(&(thread_current()->exit_sema));
			
			thread_exit();	
			break;
		default :
			printf("\n Running Default case in switch case\n");
			break;

	}
	return;
error_in_esp :

	f->eax = -1;
	f->esp = old_esp;

				put_status_in_parent(f->eax);	
	struct semaphore *a = &(thread_current()->exit_sema);

	sema_up(&(thread_current()->exit_sema));
	printf ("%s: exit(%d)\n", strtok_r(thread_name(), delimiter, &saveptr), f->eax);
	thread_exit();
}
