/**
 * collectd - src/utils_avltree.h
 * Copyright (C) 2006,2007  Florian octo Forster
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Authors:
 *   Florian octo Forster <octo at collectd.org>
 **/

#ifndef UTILS_AVLTREE_H
#define UTILS_AVLTREE_H 1

struct c_avl_tree_s;
typedef struct c_avl_tree_s c_avl_tree_t;

struct c_avl_iterator_s;
typedef struct c_avl_iterator_s c_avl_iterator_t;

/*
 * NAME
 *   c_avl_create
 *
 * DESCRIPTION
 *   Allocates a new AVL-tree.
 *
 * PARAMETERS
 *   `compare'  The function-pointer `compare' is used to compare two keys. It
 *              has to return less than zero if its first argument is smaller
 *              then the second argument, more than zero if the first argument
 *              is bigger than the second argument and zero if they are equal.
 *              If your keys are char-pointers, you can use the `strcmp'
 *              function from the libc here.
 *
 * RETURN VALUE
 *   A c_avl_tree_t-pointer upon success or NULL upon failure.
 */
c_avl_tree_t * c_avl_create(int (*compare)(const void *, const void *));

/*
 * NAME
 *   c_avl_destroy
 *
 * DESCRIPTION
 *   Deallocates an AVL-tree. Stored value- and key-pointer are lost, but of
 *   course not freed.
 */
void c_avl_destroy(c_avl_tree_t * t);

/*
 * NAME
 *   c_avl_insert
 *
 * DESCRIPTION
 *   Stores the key-value-pair in the AVL-tree pointed to by `t'.
 *
 * PARAMETERS
 *   `t'        AVL-tree to store the data in.
 *   `key'      Key used to store the value under. This is used to get back to
 *              the value again. The pointer is stored in an internal structure
 *              and _not_ copied. So the memory pointed to may _not_ be freed
 *              before this entry is removed. You can use the `rkey' argument
 *              to `avl_remove' to get the original pointer back and free it.
 *   `value'    Value to be stored.
 *
 * RETURN VALUE
 *   Zero upon success, non-zero otherwise. It's less than zero if an error
 *   occurred or greater than zero if the key is already stored in the tree.
 */
int c_avl_insert(c_avl_tree_t * t, void * key, void * value);

/*
 * NAME
 *   c_avl_remove
 *
 * DESCRIPTION
 *   Removes a key-value-pair from the tree t. The stored key and value may be
 *   returned in `rkey' and `rvalue'.
 *
 * PARAMETERS
 *   `t'	AVL-tree to remove key-value-pair from.
 *   `key'      Key to identify the entry.
 *   `rkey'     Pointer to a pointer in which to store the key. May be NULL.
 *              Since the `key' pointer is not copied when creating an entry,
 *              the pointer may not be available anymore from outside the tree.
 *              You can use this argument to get the actual pointer back and
 *              free the memory pointed to by it.
 *   `rvalue'   Pointer to a pointer in which to store the value. May be NULL.
 *
 * RETURN VALUE
 *   Zero upon success or non-zero if the key isn't found in the tree.
 */
int c_avl_remove(c_avl_tree_t * t,
				 const void * key,
				 void ** rkey,
				 void ** rvalue);

/*
 * NAME
 *   c_avl_get
 *
 * DESCRIPTION
 *   Retrieve the `value' belonging to `key'.
 *
 * PARAMETERS
 *   `t'	AVL-tree to get the value from.
 *   `key'      Key to identify the entry.
 *   `value'    Pointer to a pointer in which to store the value. May be NULL.
 *
 * RETURN VALUE
 *   Zero upon success or non-zero if the key isn't found in the tree.
 */
int c_avl_get(c_avl_tree_t * t, const void * key, void ** value);

/*
 * NAME
 *   c_avl_pick
 *
 * DESCRIPTION
 *   Remove a (pseudo-)random element from the tree and return its `key' and
 *   `value'. Entries are not returned in any particular order. This function
 *   is intended for cache-flushes that don't care about the order but simply
 *   want to remove all elements, one at a time.
 *
 * PARAMETERS
 *   `t'	AVL-tree to get the value from.
 *   `key'      Pointer to a pointer in which to store the key.
 *   `value'    Pointer to a pointer in which to store the value.
 *
 * RETURN VALUE
 *   Zero upon success or non-zero if the tree is empty or key or value is
 *   NULL.
 */
int c_avl_pick(c_avl_tree_t * t, void ** key, void ** value);

c_avl_iterator_t * c_avl_get_iterator(c_avl_tree_t * t);
int c_avl_iterator_next(c_avl_iterator_t * iter, void ** key, void ** value);
int c_avl_iterator_prev(c_avl_iterator_t * iter, void ** key, void ** value);
void c_avl_iterator_destroy(c_avl_iterator_t * iter);

/*
 * NAME
 *   c_avl_size
 *
 * DESCRIPTION
 *   Return the size (number of nodes) of the specified tree.
 *
 * PARAMETERS
 *   `t'        AVL-tree to get the size of.
 *
 * RETURN VALUE
 *   Number of nodes in the tree, 0 if the tree is empty or NULL.
 */
int c_avl_size(c_avl_tree_t * t);

#endif /* UTILS_AVLTREE_H */
