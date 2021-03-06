#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>
#include "filesys/file.h"
#include "filesys/filesys.h"

#include "threads/synch.h"

struct list blocked_list;
/* States in a thread's life cycle. */
enum thread_status
{
	THREAD_RUNNING,     /* Running thread. */
	THREAD_READY,       /* Not running but ready to run. */
	THREAD_BLOCKED,     /* Waiting for an event to trigger. */
	THREAD_DYING        /* About to be destroyed. */
};

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t) -1)          /* Error value for tid_t. */

/* Thread priorities. */
#define PRI_MIN 0                       /* Lowest priority. */
#define PRI_DEFAULT 31                  /* Default priority. */
#define PRI_MAX 63                      /* Highest priority. */
/* Structure for storing the open files of a thread */
struct fd_elem
{
	bool used;
	struct file *file;
	
};

/* Structure for storing the details of a single child
	Whenever the child exits, it updates the status field.
	After a wait call is successfully executed, the repeat and invalid bit is set to true.
	tid contains the thread_id of the child pointed by "child".	
 */
struct s_child
{
	tid_t tid;
	struct thread *child;	
	int status;
	bool repeat;
	bool invalid;
};
/* A kernel thread or user process.

   Each thread structure is stored in its own 4 kB page.  The
   thread structure itself sits at the very bottom of the page
   (at offset 0).  The rest of the page is reserved for the
   thread's kernel stack, which grows downward from the top of
   the page (at offset 4 kB).  Here's an illustration:

   4 kB +---------------------------------+
   |          kernel stack           |
   |                |                |
   |                |                |
   |                V                |
   |         grows downward          |
   |                                 |
   |                                 |
   |                                 |
   |                                 |
   |                                 |
   |                                 |
   |                                 |
   |                                 |
   +---------------------------------+
   |              magic              |
   |                :                |
   |                :                |
   |               name              |
   |              status             |
   0 kB +---------------------------------+

   The upshot of this is twofold:

   1. First, `struct thread' must not be allowed to grow too
   big.  If it does, then there will not be enough room for
   the kernel stack.  Our base `struct thread' is only a
   few bytes in size.  It probably should stay well under 1
   kB.

   2. Second, kernel stacks must not be allowed to grow too
   large.  If a stack overflows, it will corrupt the thread
   state.  Thus, kernel functions should not allocate large
   structures or arrays as non-static local variables.  Use
   dynamic allocation with malloc() or palloc_get_page()
   instead.

   The first symptom of either of these problems will probably be
   an assertion failure in thread_current(), which checks that
   the `magic' member of the running thread's `struct thread' is
   set to THREAD_MAGIC.  Stack overflow will normally change this
   value, triggering the assertion. */
/* The `elem' member has a dual purpose.  It can be an element in
   the run queue (thread.c), or it can be an element in a
   semaphore wait list (synch.c).  It can be used these two ways
   only because they are mutually exclusive: only a thread in the
   ready state is on the run queue, whereas only a thread in the
   blocked state is on a semaphore wait list. */

struct thread
{
	/* Owned by thread.c. */
	tid_t tid;                          /* Thread identifier. */
	enum thread_status status;          /* Thread state. */
	char name[16];                      /* Name (for debugging purposes). */
	uint8_t *stack;                     /* Saved stack pointer. */
	int priority;                       /* Priority. */
	int base_priority; 		/*To regain the original priority at the end of all donations*/
	struct list_elem allelem;           /* List element for all threads list. */
	struct thread* donated_to;
	/* Shared between thread.c and synch.c. */
	struct list_elem elem;              /* List element. */

	/* for blocking list !!*/
	struct list_elem elem1;
	struct list retrace_priority_list;

// Pointer for storing the information about childs
	struct s_child *child_threads;
// The current count of children for this thread.
	int child_cnt;
// pointer to the parent thread.
	struct thread *parent;
// Semaphore used in process_wait, so that parent can wait for the child.
	struct semaphore exit_sema;

/* Array storing the current open files for this thread. The index of the array denotes the 
 file Descriptor for that file.
	Total of 128 files can be opened at the same time. 	*/
	struct fd_elem fd_arr[128];

/* Pointer to the executable file of the current user-thread.
	This pointer is required for the functionality of "Denying writes to the executables"
	This file will be closed when the thread exits. */
	struct file *exec_file;
#ifdef USERPROG
	/* Owned by userprog/process.c. */
	uint32_t *pagedir;                  /* Page directory. */
#endif

	/* Owned by thread.c. */
	unsigned magic;                     /* Detects stack overflow. */
	//Time till when it will sleep.
	int64_t end_time;
};

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

void thread_init (void);
void thread_start (void);

void thread_tick (void);
void thread_print_stats (void);

typedef void thread_func (void *aux);
tid_t thread_create (const char *name, int priority, thread_func *, void *);

void thread_block (void);
void thread_unblock (struct thread *);

struct thread *thread_current (void);
tid_t thread_tid (void);
const char *thread_name (void);

void thread_exit (void) NO_RETURN;
void thread_yield (void);

/* Performs some operation on thread t, given auxiliary data AUX. */
typedef void thread_action_func (struct thread *t, void *aux);
void thread_foreach (thread_action_func *, void *);

int thread_get_priority (void);
void thread_set_priority (int);

int thread_get_nice (void);
void thread_set_nice (int);
int thread_get_recent_cpu (void);
int thread_get_load_avg (void);



#endif /* threads/thread.h */
