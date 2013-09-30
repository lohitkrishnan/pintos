#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "lib/user/syscall.h"
#include<string.h>
#include "filesys/file.h"
#include "filesys/filesys.h"

static void syscall_handler (struct intr_frame *);
//Semaphore x is used for synchronization between all the file system-calls
struct semaphore x;

	void
syscall_init (void) 
{
	intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
	sema_init(&x, 1);
}

//Check if esp is valid
bool check_esp(struct intr_frame *f)
{
	return (!(is_user_vaddr((int *)f->esp) && (int *)f->esp != NULL
				&& pagedir_get_page(thread_current()->pagedir, (f->esp)) != NULL));
}

/* 
   This function checks whether pointer "p" of TYPE "type" is  valid or not
   Returns 1 if invalid
   Returns 0 if valid.
 */
bool check(void *p, char *type)
{

	if(!strcmp(type, "char *"))
		return (!(is_user_vaddr((char *)p) && (char *)p != NULL
					&& pagedir_get_page(thread_current()->pagedir, (p)) != NULL)); 
	else if (!strcmp(type, "int *"))
		return (!(is_user_vaddr((int *)p) && (int *)p != NULL
					&& pagedir_get_page(thread_current()->pagedir, (p)) != NULL));
	else
		printf("\nType is not defined in check() !!\n");
}
/* 
   This function adds file fp into the array "fd_arr" of the current thread.
   It returns the File descriptor fd
   If the max limit of open files have reached then it returns -1.
 */
int add_file_to_arr(struct file *fp)
{
	int i;
	struct thread *curr = thread_current();
	for (i = 2; i < 128; i++)
	{
		if(curr->fd_arr[i].used == false)
		{
			curr->fd_arr[i].file = fp;	
			curr->fd_arr[i].used = true;
			return i;
		}
	}
	return -1;
}

void exit_syscall(int status)
{
	char *saveptr;
	put_status_in_parent(status);
	printf ("%s: exit(%d)\n", strtok_r(thread_name(), " ", &saveptr), status);
	sema_up(&(thread_current()->exit_sema));
	file_close(thread_current()->exec_file);
	close_all_files();
	thread_exit();

}


/*
   From the File Descriptor fd, it returns the file pointer to the specific file.
   If the fd is invalid then it returns NULL.
 */
struct file* get_file(int fd)
{
	struct file *fp = NULL;
	struct thread *curr = thread_current();

	if((fd < 2) || fd >=128 )
		return NULL;
	if(curr->fd_arr[fd].used == false)
	{
		return NULL;
	}
	else
	{
		return curr->fd_arr[fd].file;
	}
}

	static void
syscall_handler (struct intr_frame *f UNUSED) 
{

	int fd;
	const void *buf;
	unsigned int size;
	unsigned char c;
	int index;
	int status;
	int tid;
	pid_t pid;
	char *saveptr;
	char *delimiter = " ";
	char *file, *file_name;
	char type[8];
	struct file *s_file;
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
			sema_down(&x);
			fd = *(int *)(f->esp);

			(f->esp) += sizeof(int);
			if(check_esp(f)){
				goto error_in_esp;}

			buf = *(int *)(f->esp);

			(f->esp) += sizeof(int);

			if(check_esp(f)){
				goto error_in_esp;}
			if(check(buf, "char *"))
				goto error_in_esp;

			size = *(unsigned int *)(f->esp);

			if(fd == 1){
				putbuf(buf, size);
				f->eax = 0;
			}
			else if(fd == 0 || fd >= 128)
				f->eax = -1;
			else 
			{	
				s_file = get_file(fd);
				if (s_file == NULL)
				{
					f->eax = -1;
				}
				else
				{
					f->eax = file_write(s_file, buf, size);
				}
			}
			f->esp = old_esp;
			sema_up(&x);
			break;

		case SYS_WAIT:
			pid = *(pid_t *)(f->esp);
			f->eax = process_wait(pid);
			f->esp = old_esp;
			break;
		case SYS_EXEC:
			file = *(char **)(f->esp);

			if(check(file, "char *"))
				goto error_in_esp;
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
			break;
		case SYS_HALT:
			shutdown_power_off();	
			break;
			/*
			   Steps done in SYS_EXIT system call.
			   1. Put the status in parent.
			   2. Do the proper printf statement.
			   3. Signal to the parent via "exit_sema" semaphore indicating that 
			   this thread is going to be exitted
			   4. Close the executable file of the current thread.
			   5. Close all the files of this current thread.
			 */
		case SYS_EXIT:
			status = *(int *)(f->esp);
			f->eax = status;
			f->esp = old_esp;	
			
			exit_syscall(status);
			/*
			put_status_in_parent(status);
			printf ("%s: exit(%d)\n", strtok_r(thread_name(), delimiter, &saveptr), f->eax);
			sema_up(&(thread_current()->exit_sema));
			file_close(thread_current()->exec_file);
			close_all_files();
			thread_exit();	*/

			break;
		case SYS_CREATE:
			sema_down(&x);
			file_name = *(char **)f->esp;
			if(check(file_name, "char *"))
				goto error_in_esp;
			f->esp += sizeof(char *);
			size = *(int *)f->esp;
			f->eax = filesys_create(file_name, size);
			f->esp = old_esp;
			sema_up(&x);
			break;
			/*
			   Open the file.
			   If the file is invalid, return -1.
			   For valid files, get the file descriptor using a call to add_file_to_arr function.
			   Return the File-descriptor fd.
			 */
		case SYS_OPEN:
			sema_down(&x);
			file_name = *(char **)f->esp;
			if(check(file_name, "char *"))
				goto error_in_esp;
			s_file = filesys_open(file_name);
			if(s_file == NULL)
			{
				f->eax = -1;
			}
			else
			{
				fd = add_file_to_arr(s_file);
				f->eax = fd;	
			}
			f->esp = old_esp;
			sema_up(&x);
			break;
			/*
			   1. Get the file from the file descriptor fd using get_file function.
			   2. If invalid then return -1.
			   3. For valid files, close the file and mark the space of the specified fd as free.
			 */
		case SYS_CLOSE:
			sema_down(&x);
			fd = *(int *)f->esp;
			s_file = get_file(fd);
			if(s_file == NULL)
			{	
				f->eax = -1;
			}
			else
			{
				thread_current()->fd_arr[fd].used = false;
				file_close(s_file);
			}
			f->esp = old_esp;
			sema_up(&x);
			break;
		case SYS_READ:
			sema_down(&x);
			fd = *(int *)f->esp;
			f->esp += sizeof(int);

			file = *(char **)f->esp;
			if(check(file, "char *"))
				goto error_in_esp;
			f->esp += sizeof(char *);
			size = *(unsigned int *)f->esp;

			if(fd == 0)
			{
				index = 0;
				c = input_getc();
				while(c != '\n')
				{
					file[index++] = c;
					c = input_getc();	
				}
				f->eax = index;
			}
			else
			{

				s_file = get_file(fd);
				if(s_file == NULL)
				{	
					f->eax = -1;
				}
				else
				{
					file_deny_write(s_file);
					f->eax = file_read(s_file, file, size);
					file_allow_write(s_file);
				}
			}
			f->esp = old_esp;
			sema_up(&x);
			break;
		case SYS_FILESIZE:
			sema_down(&x);
			fd = *(int *)f->esp;
			if((fd >=0 && fd < 2) || fd >= 128)
				f->eax = -1;
			else
			{
				s_file = get_file(fd);
				if(s_file == NULL)
				{

					f->eax = -1;
				}
				else
				{
					f->eax = file_length(s_file);
				}
			}
			f->esp =old_esp;
			sema_up(&x);
			break;
		case SYS_SEEK:
			sema_down(&x);
			fd = *(int *)f->esp;

			f->esp += sizeof(int);
			if(check_esp(f))
				goto error_in_esp;
			size = *(unsigned int *)f->esp;

			s_file = get_file(fd);
			if(s_file == NULL)
			{
				f->eax = -1;
			}
			else
			{
				f->eax = 0;
				file_seek(s_file, size);
			}
			sema_up(&x);
			f->esp = old_esp;
			break;
		case SYS_TELL:
			sema_down(&x);
			fd = *(int *)f->esp;
			s_file = get_file(fd);
			if (s_file == NULL)
			{
				f->eax = -1;
			}
			else
			{
				f->eax = file_tell(s_file);
			}
			f->esp = old_esp;
			sema_up(&x);
			break;
		case SYS_REMOVE:
			sema_down(&x);

			file_name = *(char **)f->esp;
			if(check(file_name, "char *"))
				goto error_in_esp;
			f->eax =filesys_remove(file_name);
			f->esp = old_esp;
			sema_up(&x);
			break;
		default :
			printf("\n Running Default case in switch case\n");
			break;

	}
	return;
error_in_esp :

	f->eax = -1;
	f->esp = old_esp;

	sema_up(&x);
	exit_syscall(-1);
/*
	put_status_in_parent(f->eax);	
	sema_up(&(thread_current()->exit_sema));
	file_close(thread_current()->exec_file);
	close_all_files();
	printf ("%s: exit(%d)\n", strtok_r(thread_name(), delimiter, &saveptr), f->eax);
	thread_exit();
*/
}
