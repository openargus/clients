#ifndef UBI_SPLAYTREE_H
#define UBI_SPLAYTREE_H
/* $Id: ubi_SplayTree.h,v 1.1 2004/05/12 00:04:26 qosient Exp $ */
/* ========================================================================== **
 *                              ubi_SplayTree.h
 *
 *  Copyright (C) 1993-1998 by Christopher R. Hertel
 *
 *  Email: crh@ubiqx.mn.org
 * -------------------------------------------------------------------------- **
 *
 *  This module implements "splay" trees.  Splay trees are binary trees
 *  that are rearranged (splayed) whenever a node is accessed.  The
 *  splaying process *tends* to make the tree bushier (improves balance),
 *  and the nodes that are accessed most frequently *tend* to be closer to
 *  the top.
 *
 *  References: "Self-Adjusting Binary Search Trees", by Daniel Sleator and
 *              Robert Tarjan.  Journal of the Association for Computing
 *              Machinery Vol 32, No. 3, July 1985 pp. 652-686
 *
 *    See also: http://www.cs.cmu.edu/~sleator/ 
 *
 * -------------------------------------------------------------------------- **
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Library General Public
 *  License as published by the Free Software Foundation; either
 *  version 2 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Library General Public License for more details.
 *
 *  You should have received a copy of the GNU Library General Public
 *  License along with this library; if not, write to the Free
 *  Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * ========================================================================== **
 */

#include "ubi_BinTree.h" /* Base binary tree functions, types, etc.  */

/* ========================================================================== **
 * Function prototypes...
 */

ubi_trBool ubi_sptInsert( ubi_btRootPtr  RootPtr,
                          ubi_btNodePtr  NewNode,
                          ubi_btItemPtr  ItemPtr,
                          ubi_btNodePtr *OldNode );
  /* ------------------------------------------------------------------------ **
   * This function uses a non-recursive algorithm to add a new element to the
   * splay tree.
   *
   *  Input:   RootPtr  -  a pointer to the ubi_btRoot structure that indicates
   *                       the root of the tree to which NewNode is to be added.
   *           NewNode  -  a pointer to an ubi_btNode structure that is NOT
   *                       part of any tree.
   *           ItemPtr  -  A pointer to the sort key that is stored within
   *                       *NewNode.  ItemPtr MUST point to information stored
   *                       in *NewNode or an EXACT DUPLICATE.  The key data
   *                       indicated by ItemPtr is used to place the new node
   *                       into the tree.
   *           OldNode  -  a pointer to an ubi_btNodePtr.  When searching
   *                       the tree, a duplicate node may be found.  If
   *                       duplicates are allowed, then the new node will
   *                       be simply placed into the tree.  If duplicates
   *                       are not allowed, however, then one of two things
   *                       may happen.
   *                       1) if overwritting *is not* allowed, this
   *                          function will return FALSE (indicating that
   *                          the new node could not be inserted), and
   *                          *OldNode will point to the duplicate that is
   *                          still in the tree.
   *                       2) if overwritting *is* allowed, then this
   *                          function will swap **OldNode for *NewNode.
   *                          In this case, *OldNode will point to the node
   *                          that was removed (thus allowing you to free
   *                          the node).
   *                          **  If you are using overwrite mode, ALWAYS  **
   *                          ** check the return value of this parameter! **
   *                 Note: You may pass NULL in this parameter, the
   *                       function knows how to cope.  If you do this,
   *                       however, there will be no way to return a
   *                       pointer to an old (ie. replaced) node (which is
   *                       a problem if you are using overwrite mode).
   *
   *  Output:  a boolean value indicating success or failure.  The function
   *           will return FALSE if the node could not be added to the tree.
   *           Such failure will only occur if duplicates are not allowed,
   *           nodes cannot be overwritten, AND a duplicate key was found
   *           within the tree.
   * ------------------------------------------------------------------------ **
   */

ubi_btNodePtr ubi_sptRemove( ubi_btRootPtr RootPtr, ubi_btNodePtr DeadNode );
  /* ------------------------------------------------------------------------ **
   * This function removes the indicated node from the tree.
   *
   *  Input:   RootPtr  -  A pointer to the header of the tree that contains
   *                       the node to be removed.
   *           DeadNode -  A pointer to the node that will be removed.
   *
   *  Output:  This function returns a pointer to the node that was removed
   *           from the tree (ie. the same as DeadNode).
   *
   *  Note:    The node MUST be in the tree indicated by RootPtr.  If not,
   *           strange and evil things will happen to your trees.
   * ------------------------------------------------------------------------ **
   */

ubi_btNodePtr ubi_sptLocate( ubi_btRootPtr RootPtr,
                             ubi_btItemPtr FindMe,
                             ubi_trCompOps CompOp );
  /* ------------------------------------------------------------------------ **
   * The purpose of ubi_btLocate() is to find a node or set of nodes given
   * a target value and a "comparison operator".  The Locate() function is
   * more flexible and (in the case of trees that may contain dupicate keys)
   * more precise than the ubi_btFind() function.  The latter is faster,
   * but it only searches for exact matches and, if the tree contains
   * duplicates, Find() may return a pointer to any one of the duplicate-
   * keyed records.
   *
   *  Input:
   *     RootPtr  -  A pointer to the header of the tree to be searched.
   *     FindMe   -  An ubi_btItemPtr that indicates the key for which to
   *                 search.
   *     CompOp   -  One of the following:
   *                    CompOp     Return a pointer to the node with
   *                    ------     ---------------------------------
   *                   ubi_trLT - the last key value that is less
   *                              than FindMe.
   *                   ubi_trLE - the first key matching FindMe, or
   *                              the last key that is less than
   *                              FindMe.
   *                   ubi_trEQ - the first key matching FindMe.
   *                   ubi_trGE - the first key matching FindMe, or the
   *                              first key greater than FindMe.
   *                   ubi_trGT - the first key greater than FindMe.
   *  Output:
   *     A pointer to the node matching the criteria listed above under
   *     CompOp, or NULL if no node matched the criteria.
   *
   *  Notes:
   *     In the case of trees with duplicate keys, Locate() will behave as
   *     follows:
   *
   *     Find:  3                       Find: 3
   *     Keys:  1 2 2 2 3 3 3 3 3 4 4   Keys: 1 1 2 2 2 4 4 5 5 5 6
   *                  ^ ^         ^                   ^ ^
   *                 LT EQ        GT                 LE GE
   *
   *     That is, when returning a pointer to a node with a key that is LESS
   *     THAN the target key (FindMe), Locate() will return a pointer to the
   *     LAST matching node.
   *     When returning a pointer to a node with a key that is GREATER
   *     THAN the target key (FindMe), Locate() will return a pointer to the
   *     FIRST matching node.
   *
   *  See Also: ubi_btFind(), ubi_btFirstOf(), ubi_btLastOf().
   * ------------------------------------------------------------------------ **
   */

ubi_btNodePtr ubi_sptFind( ubi_btRootPtr RootPtr,
                           ubi_btItemPtr FindMe );
  /* ------------------------------------------------------------------------ **
   * This function performs a non-recursive search of a tree for any node
   * matching a specific key.
   *
   *  Input:
   *     RootPtr  -  a pointer to the header of the tree to be searched.
   *     FindMe   -  a pointer to the key value for which to search.
   *
   *  Output:
   *     A pointer to a node with a key that matches the key indicated by
   *     FindMe, or NULL if no such node was found.
   *
   *  Note:   In a tree that allows duplicates, the pointer returned *might
   *          not* point to the (sequentially) first occurance of the
   *          desired key.  In such a tree, it may be more useful to use
   *          ubi_sptLocate().
   * ------------------------------------------------------------------------ **
   */

void ubi_sptSplay( ubi_btRootPtr RootPtr,
                   ubi_btNodePtr SplayMe );
  /* ------------------------------------------------------------------------ **
   *  This function allows you to splay the tree at a given node, thus moving
   *  the node to the top of the tree.
   *
   *  Input:
   *     RootPtr  -  a pointer to the header of the tree to be splayed.
   *     SplayMe  -  a pointer to a node within the tree.  This will become
   *                 the new root node.
   *  Output: None.
   *
   *  Notes:  This is an uncharacteristic function for this group of modules
   *          in that it provides access to the internal balancing routines,
   *          which would normally be hidden.
   *          Splaying the tree will not damage it (assuming that I've done
   *          *my* job), but there is overhead involved.  I don't recommend
   *          that you use this function unless you understand the underlying
   *          Splay Tree principles involved.
   * ------------------------------------------------------------------------ **
   */

int ubi_sptModuleID( int size, char *list[] );
  /* ------------------------------------------------------------------------ **
   * Returns a set of strings that identify the module.
   *
   *  Input:  size  - The number of elements in the array <list>.
   *          list  - An array of pointers of type (char *).  This array
   *                  should, initially, be empty.  This function will fill
   *                  in the array with pointers to strings.
   *  Output: The number of elements of <list> that were used.  If this value
   *          is less than <size>, the values of the remaining elements are
   *          not guaranteed.
   *
   *  Notes:  Please keep in mind that the pointers returned indicate strings
   *          stored in static memory.  Don't free() them, don't write over
   *          them, etc.  Just read them.
   * ------------------------------------------------------------------------ **
   */

/* -------------------------------------------------------------------------- **
 * Masquarade...
 *
 * This set of defines allows you to write programs that will use any of the
 * implemented binary tree modules (currently BinTree, AVLtree, and SplayTree).
 * Instead of using ubi_bt..., use ubi_tr..., and select the tree type by
 * including the appropriate module header.
 */

#undef ubi_trInsert
#undef ubi_trRemove
#undef ubi_trLocate
#undef ubi_trFind
#undef ubi_trModuleID

#define ubi_trInsert( Rp, Nn, Ip, On ) \
        ubi_sptInsert( (ubi_btRootPtr)(Rp), (ubi_btNodePtr)(Nn), \
                       (ubi_btItemPtr)(Ip), (ubi_btNodePtr *)(On) )

#define ubi_trRemove( Rp, Dn ) \
        ubi_sptRemove( (ubi_btRootPtr)(Rp), (ubi_btNodePtr)(Dn) )

#define ubi_trLocate( Rp, Ip, Op ) \
        ubi_sptLocate( (ubi_btRootPtr)(Rp), \
                       (ubi_btItemPtr)(Ip), \
                       (ubi_trCompOps)(Op) )

#define ubi_trFind( Rp, Ip ) \
        ubi_sptFind( (ubi_btRootPtr)(Rp), (ubi_btItemPtr)(Ip) )

#define ubi_trSplay( Rp, Sm ) \
        ubi_sptSplay( (ubi_btRootPtr)(Rp), (ubi_btNodePtr)(Sm) )

#define ubi_trModuleID( s, l ) ubi_sptModuleID( s, l )

/* ================================ The End ================================= */
#endif /* UBI_SPLAYTREE_H */
