#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include "postgres.h"
#include "port.h"
#include "libpq/auth.h"
#include "catalog/pg_authid.h"
#include "utils/guc.h"
#include "storage/proc.h"
#include "utils/acl.h"
#include "utils/syscache.h"
#include "utils/catcache.h"
#include "nodes/pg_list.h"
#include "catalog/pg_auth_members.h"
#define MAX_SEARCH_OID 6000000
PG_MODULE_MAGIC;
typedef void (*ClientAuthentication_hook_type) (Port *, int);
static ClientAuthentication_hook_type prev_client_auth_hook = NULL;
static List *cached_membership_roles = NIL;
static Oid	cached_member_role = InvalidOid;
void _PG_init(void);

static List *
roles_is_member_of(Oid roleid)
{
	List	   *roles_list;
	ListCell   *l;
	List	   *new_cached_membership_roles;
	MemoryContext oldctx;

	/* If cache is already valid, just return the list */
	if (OidIsValid(cached_member_role) && cached_member_role == roleid)
		return cached_membership_roles;

	/*
	 * Find all the roles that roleid is a member of, including multi-level
	 * recursion.  The role itself will always be the first element of the
	 * resulting list.
	 *
	 * Each element of the list is scanned to see if it adds any indirect
	 * memberships.  We can use a single list as both the record of
	 * already-found memberships and the agenda of roles yet to be scanned.
	 * This is a bit tricky but works because the foreach() macro doesn't
	 * fetch the next list element until the bottom of the loop.
	 */
	roles_list = list_make1_oid(roleid);
	foreach(l, roles_list)
	{
		Oid			memberid = lfirst_oid(l);
		CatCList   *memlist;
		int			i;
		/* Find roles that memberid is directly a member of */
		memlist = SearchSysCacheList1(AUTHMEMMEMROLE, ObjectIdGetDatum(roleid));
		for (i = 0; i < memlist->n_members; i++)
		{
			HeapTuple	tup = &memlist->members[i]->tuple;
			Oid			otherid = ((Form_pg_auth_members) GETSTRUCT(tup))->roleid;
			/*
			 * Even though there shouldn't be any loops in the membership
			 * graph, we must test for having already seen this role. It is
			 * legal for instance to have both A->B and A->C->B.
			 */
			roles_list = list_append_unique_oid(roles_list, otherid);
		}
		ReleaseSysCacheList(memlist);
	}
	return(roles_list);
}

static bool
is_member_of_role_rpe(Oid member, Oid role)
{
	/* Fast path for simple case */
	if (member == role)
		return true;
	/*
	 * Find all the roles that member is a member of, including multi-level
	 * recursion, then see if target role is any one of them.
	 */
	return list_member_oid(roles_is_member_of(member), role);
}

static bool 
is_equal_premissions(Form_pg_authid src_roleform, Oid search_oid)
{
	HeapTuple		role_tup;
	Form_pg_authid	rform;
	bool			result = false;

	role_tup = SearchSysCache1(AUTHOID, ObjectIdGetDatum(search_oid));
	if (HeapTupleIsValid(role_tup))
	{
		rform = (Form_pg_authid)GETSTRUCT(role_tup);
		if (
			rform->rolinherit == src_roleform->rolinherit && \
			rform->rolcreaterole == src_roleform->rolcreaterole && \
			rform->rolcreatedb == src_roleform->rolcreatedb && \
			rform->rolcanlogin == src_roleform->rolcanlogin && \
			rform->rolreplication == src_roleform->rolreplication && \
			rform->rolconnlimit == src_roleform->rolconnlimit &&
			rform->rolcreaterextgpfd == src_roleform->rolcreaterextgpfd)
				result = true;
		ReleaseSysCache(role_tup);
	}
	return(result);
}

static	char *
get_role_name_from_oid(Oid role_oid)
{
	HeapTuple		role_tup;
	Form_pg_authid	rform;
	char			*result;

	role_tup = SearchSysCache1(AUTHOID, ObjectIdGetDatum(role_oid));
	rform = (Form_pg_authid)GETSTRUCT(role_tup);
	result = palloc(strlen(rform->rolname.data));
	strcpy(result, rform->rolname.data);
	ReleaseSysCache(role_tup);
	return(result);
}

static void 
roles_premissions_equality_hook(Port *p, int nmb)
{
	HeapTuple		role_tup;
	Form_pg_authid 	rform;
	List			*rolelist;
	Oid				search_oid = FirstNormalObjectId;
	Oid				user_oid = InvalidOid;
	char			*found_role_name;
	ListCell		*cell;

	if (p->user_name)
		user_oid = get_role_oid(p->user_name, true);
	if (OidIsValid(user_oid))
	{
		rolelist = roles_is_member_of(user_oid);
		role_tup = SearchSysCache1(AUTHOID, ObjectIdGetDatum(user_oid));
		rform = (Form_pg_authid)GETSTRUCT(role_tup);
		
		foreach(cell, rolelist)
		{
			while (search_oid < MAX_SEARCH_OID)
			{
				if (!rform->rolsuper && search_oid != user_oid && cell->data.oid_value != user_oid)
				{
					if (is_member_of_role_rpe(search_oid, cell->data.oid_value))
					{
						if (!is_equal_premissions(rform, search_oid))
						{
							found_role_name = get_role_name_from_oid(search_oid);
							ereport(ERROR,
							(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
								errmsg("Role's %s premissons are not euqual to premissions of role %s\n",
								rform->rolname.data, found_role_name)));
							pfree(found_role_name);
						}
					}
				}
				search_oid++;
			}
			search_oid = FirstNormalObjectId;
		}
		if (HeapTupleIsValid(role_tup))
			ReleaseSysCache(role_tup);
	}
}

void    
_PG_init(void)
{
    prev_client_auth_hook = ClientAuthentication_hook;
    ClientAuthentication_hook = roles_premissions_equality_hook;
}
