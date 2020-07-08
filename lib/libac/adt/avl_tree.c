/**
 * collectd - src/utils_avltree.c
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <stdlib.h>

#include "aircrack-ng/defs.h"
#include "aircrack-ng/adt/avl_tree.h"

#define BALANCE(n)                                                             \
	(((n) == NULL) ? 0                                                         \
				   : (((n)->left == NULL) ? 0 : (n)->left->height)             \
						 - (((n)->right == NULL) ? 0 : (n)->right->height))

/*
 * private data types
 */
struct c_avl_node_s
{
	void * key;
	void * value;

	int height;
	struct c_avl_node_s * left;
	struct c_avl_node_s * right;
	struct c_avl_node_s * parent;
};
typedef struct c_avl_node_s c_avl_node_t;

struct c_avl_tree_s
{
	c_avl_node_t * root;
	int (*compare)(const void *, const void *);
	int size;
};

struct c_avl_iterator_s
{
	c_avl_tree_t * tree;
	c_avl_node_t * node;
};

/*
 * private functions
 */
#if 0
static void verify_tree (c_avl_node_t *n)
{
	if (n == NULL)
		return;

	verify_tree (n->left);
	verify_tree (n->right);

	assert ((BALANCE (n) >= -1) && (BALANCE (n) <= 1));
	assert ((n->parent == NULL) || (n->parent->right == n) || (n->parent->left == n));
} /* void verify_tree */
#else
#define verify_tree(n) /**/
#endif

static void free_node(c_avl_node_t * n)
{
	if (n == NULL) return;

	if (n->left != NULL) free_node(n->left);
	if (n->right != NULL) free_node(n->right);

	free(n);
}

static int calc_height(c_avl_node_t * n)
{
	int height_left;
	int height_right;

	if (n == NULL) return 0;

	height_left = (n->left == NULL) ? 0 : n->left->height;
	height_right = (n->right == NULL) ? 0 : n->right->height;

	return ((height_left > height_right) ? height_left : height_right) + 1;
} /* int calc_height */

static c_avl_node_t * search(c_avl_tree_t * t, const void * key)
{
	c_avl_node_t * n;
	int cmp;

	n = t->root;
	while (n != NULL)
	{
		cmp = t->compare(key, n->key);
		if (cmp == 0)
			return n;
		else if (cmp < 0)
			n = n->left;
		else
			n = n->right;
	}

	return NULL;
}

/*         (x)             (y)
 *        /   \           /   \
 *     (y)    /\         /\    (x)
 *    /   \  /_c\  ==>  / a\  /   \
 *   /\   /\           /____\/\   /\
 *  / a\ /_b\               /_b\ /_c\
 * /____\
 */
static c_avl_node_t * rotate_right(c_avl_tree_t * t, c_avl_node_t * x)
{
	c_avl_node_t * p;
	c_avl_node_t * y;
	c_avl_node_t * b;

	assert(x != NULL);
	assert(x->left != NULL);

	p = x->parent;
	y = x->left;
	b = y->right;

	x->left = b;
	if (b != NULL) b->parent = x;

	x->parent = y;
	y->right = x;

	y->parent = p;
	assert((p == NULL) || (p->left == x) || (p->right == x));
	if (p == NULL)
		t->root = y;
	else if (p->left == x)
		p->left = y;
	else
		p->right = y;

	x->height = calc_height(x);
	y->height = calc_height(y);

	return y;
} /* void rotate_right */

/*
 *    (x)                   (y)
 *   /   \                 /   \
 *  /\    (y)           (x)    /\
 * /_a\  /   \   ==>   /   \  / c\
 *      /\   /\       /\   /\/____\
 *     /_b\ / c\     /_a\ /_b\
 *         /____\
 */
static c_avl_node_t * rotate_left(c_avl_tree_t * t, c_avl_node_t * x)
{
	c_avl_node_t * p;
	c_avl_node_t * y;
	c_avl_node_t * b;

	assert(x != NULL);
	assert(x->right != NULL);

	p = x->parent;
	y = x->right;
	b = y->left;

	x->right = b;
	if (b != NULL) b->parent = x;

	x->parent = y;
	y->left = x;

	y->parent = p;
	assert((p == NULL) || (p->left == x) || (p->right == x));
	if (p == NULL)
		t->root = y;
	else if (p->left == x)
		p->left = y;
	else
		p->right = y;

	x->height = calc_height(x);
	y->height = calc_height(y);

	return y;
} /* void rotate_left */

static c_avl_node_t * rotate_left_right(c_avl_tree_t * t, c_avl_node_t * x)
{
	rotate_left(t, x->left);
	return rotate_right(t, x);
} /* void rotate_left_right */

static c_avl_node_t * rotate_right_left(c_avl_tree_t * t, c_avl_node_t * x)
{
	rotate_right(t, x->right);
	return rotate_left(t, x);
} /* void rotate_right_left */

static void rebalance(c_avl_tree_t * t, c_avl_node_t * n)
{
	int b_top;
	int b_bottom;

	while (n != NULL)
	{
		b_top = BALANCE(n);
		assert((b_top >= -2) && (b_top <= 2));

		if (b_top == -2)
		{
			assert(n->right != NULL);
			b_bottom = BALANCE(n->right);
			assert((b_bottom >= -1) && (b_bottom <= 1));
			if (b_bottom == 1)
				n = rotate_right_left(t, n);
			else
				n = rotate_left(t, n);
		}
		else if (b_top == 2)
		{
			assert(n->left != NULL);
			b_bottom = BALANCE(n->left);
			assert((b_bottom >= -1) && (b_bottom <= 1));
			if (b_bottom == -1)
				n = rotate_left_right(t, n);
			else
				n = rotate_right(t, n);
		}
		else
		{
			int height = calc_height(n);
			if (height == n->height) break;
			n->height = height;
		}

		assert(n->height == calc_height(n));

		n = n->parent;
	} /* while (n != NULL) */
} /* void rebalance */

static c_avl_node_t * c_avl_node_next(c_avl_node_t * n)
{
	c_avl_node_t * r; /* return node */

	if (n == NULL)
	{
		return NULL;
	}

	/* If we can't descent any further, we have to backtrack to the first
	 * parent that's bigger than we, i. e. who's _left_ child we are. */
	if (n->right == NULL)
	{
		r = n->parent;
		while ((r != NULL) && (r->parent != NULL))
		{
			if (r->left == n) break;
			n = r;
			r = n->parent;
		}

		/* n->right == NULL && r == NULL => t is root and has no next
		 * r->left != n => r->right = n => r->parent == NULL */
		if ((r == NULL) || (r->left != n))
		{
			assert((r == NULL) || (r->parent == NULL));
			return NULL;
		}
		else
		{
			assert(r->left == n);
			return r;
		}
	}
	else
	{
		r = n->right;
		while (r->left != NULL) r = r->left;
	}

	return r;
} /* c_avl_node_t *c_avl_node_next */

static c_avl_node_t * c_avl_node_prev(c_avl_node_t * n)
{
	c_avl_node_t * r; /* return node */

	if (n == NULL)
	{
		return NULL;
	}

	/* If we can't descent any further, we have to backtrack to the first
	 * parent that's smaller than we, i. e. who's _right_ child we are. */
	if (n->left == NULL)
	{
		r = n->parent;
		while ((r != NULL) && (r->parent != NULL))
		{
			if (r->right == n) break;
			n = r;
			r = n->parent;
		}

		/* n->left == NULL && r == NULL => t is root and has no next
		 * r->right != n => r->left = n => r->parent == NULL */
		if ((r == NULL) || (r->right != n))
		{
			assert((r == NULL) || (r->parent == NULL));
			return NULL;
		}
		else
		{
			assert(r->right == n);
			return r;
		}
	}
	else
	{
		r = n->left;
		while (r->right != NULL) r = r->right;
	}

	return r;
} /* c_avl_node_t *c_avl_node_prev */

static int _remove(c_avl_tree_t * t, c_avl_node_t * n)
{
	assert((t != NULL) && (n != NULL));

	if (n && (n->left != NULL) && (n->right != NULL))
	{
		c_avl_node_t * r; /* replacement node */
		if (BALANCE(n) > 0) /* left subtree is higher */
		{
			assert(n->left != NULL); //-V547
			r = c_avl_node_prev(n);
		}
		else /* right subtree is higher */
		{
			assert(n->right != NULL); //-V547
			r = c_avl_node_next(n);
		}

		ALLEGE(r != NULL && ((r->left == NULL) || (r->right == NULL)));

		/* copy content */
		n->key = r->key;
		n->value = r->value;

		n = r;
	}

	ALLEGE(n != NULL && ((n->left == NULL) || (n->right == NULL)));

	if ((n->left == NULL) && (n->right == NULL))
	{
		/* Deleting a leave is easy */
		if (n->parent == NULL)
		{
			assert(t->root == n);
			t->root = NULL;
		}
		else
		{
			assert((n->parent->left == n) || (n->parent->right == n));
			if (n->parent->left == n)
				n->parent->left = NULL;
			else
				n->parent->right = NULL;

			rebalance(t, n->parent);
		}

		free_node(n);
	}
	else if (n->left == NULL)
	{
		assert(BALANCE(n) == -1); //-V547
		assert((n->parent == NULL) || (n->parent->left == n)
			   || (n->parent->right == n));
		if (n->parent == NULL)
		{
			assert(t->root == n);
			t->root = n->right;
		}
		else if (n->parent->left == n)
		{
			n->parent->left = n->right;
		}
		else
		{
			n->parent->right = n->right;
		}
		ALLEGE(n->right != NULL);
		n->right->parent = n->parent;

		if (n->parent != NULL) rebalance(t, n->parent);

		n->right = NULL;
		free_node(n);
	}
	else if (n->right == NULL)
	{
		assert(BALANCE(n) == 1); //-V547
		assert((n->parent == NULL) || (n->parent->left == n)
			   || (n->parent->right == n));
		if (n->parent == NULL)
		{
			assert(t->root == n);
			t->root = n->left;
		}
		else if (n->parent->left == n)
		{
			n->parent->left = n->left;
		}
		else
		{
			n->parent->right = n->left;
		}
		n->left->parent = n->parent;

		if (n->parent != NULL) rebalance(t, n->parent);

		n->left = NULL;
		free_node(n);
	}
	else
	{
		assert(0);
	}

	return 0;
} /* void *_remove */

/*
 * public functions
 */
c_avl_tree_t * c_avl_create(int (*compare)(const void *, const void *))
{
	c_avl_tree_t * t;

	if (compare == NULL) return NULL;

	if ((t = malloc(sizeof(*t))) == NULL) return NULL;

	t->root = NULL;
	t->compare = compare;
	t->size = 0;

	return t;
}

void c_avl_destroy(c_avl_tree_t * t)
{
	if (t == NULL) return;
	free_node(t->root);
	free(t);
}

int c_avl_insert(c_avl_tree_t * t, void * key, void * value)
{
	c_avl_node_t * new;
	c_avl_node_t * nptr;
	int cmp;

	if ((new = malloc(sizeof(*new))) == NULL) return -1;

	new->key = key;
	new->value = value;
	new->height = 1;
	new->left = NULL;
	new->right = NULL;

	if (t->root == NULL)
	{
		new->parent = NULL;
		t->root = new;
		t->size = 1;
		return 0;
	}

	nptr = t->root;
	while (42)
	{
		cmp = t->compare(nptr->key, new->key);
		if (cmp == 0)
		{
			free_node(new);
			return 1;
		}
		else if (cmp < 0)
		{
			/* nptr < new */
			if (nptr->right == NULL)
			{
				nptr->right = new;
				new->parent = nptr;
				rebalance(t, nptr);
				break;
			}
			else
			{
				nptr = nptr->right;
			}
		}
		else /* if (cmp > 0) */
		{
			/* nptr > new */
			if (nptr->left == NULL)
			{
				nptr->left = new;
				new->parent = nptr;
				rebalance(t, nptr);
				break;
			}
			else
			{
				nptr = nptr->left;
			}
		}
	} /* while (42) */

	verify_tree(t->root);
	++t->size;
	return 0;
} /* int c_avl_insert */

int c_avl_remove(c_avl_tree_t * t,
				 const void * key,
				 void ** rkey,
				 void ** rvalue)
{
	c_avl_node_t * n;
	int status;

	assert(t != NULL);

	n = search(t, key);
	if (n == NULL) return -1;

	if (rkey != NULL) *rkey = n->key;
	if (rvalue != NULL) *rvalue = n->value;

	status = _remove(t, n);
	verify_tree(t->root);
	--t->size;
	return status;
} /* void *c_avl_remove */

int c_avl_get(c_avl_tree_t * t, const void * key, void ** value)
{
	c_avl_node_t * n;

	assert(t != NULL);

	n = search(t, key);
	if (n == NULL) return -1;

	if (value != NULL) *value = n->value;

	return 0;
}

int c_avl_pick(c_avl_tree_t * t, void ** key, void ** value)
{
	c_avl_node_t * n;
	c_avl_node_t * p;

	assert(t != NULL);

	if ((key == NULL) || (value == NULL)) return -1;
	if (t->root == NULL) return -1;

	n = t->root;
	while ((n->left != NULL) || (n->right != NULL))
	{
		if (n->left == NULL)
		{
			n = n->right;
			continue;
		}
		else if (n->right == NULL)
		{
			n = n->left;
			continue;
		}

		if (n->left->height > n->right->height)
			n = n->left;
		else
			n = n->right;
	}

	p = n->parent;
	if (p == NULL)
		t->root = NULL;
	else if (p->left == n)
		p->left = NULL;
	else
		p->right = NULL;

	*key = n->key;
	*value = n->value;

	free_node(n);
	--t->size;
	rebalance(t, p);

	return 0;
} /* int c_avl_pick */

c_avl_iterator_t * c_avl_get_iterator(c_avl_tree_t * t)
{
	c_avl_iterator_t * iter;

	if (t == NULL) return NULL;

	iter = calloc(1, sizeof(*iter));
	if (iter == NULL) return NULL;
	iter->tree = t;

	return iter;
} /* c_avl_iterator_t *c_avl_get_iterator */

int c_avl_iterator_next(c_avl_iterator_t * iter, void ** key, void ** value)
{
	c_avl_node_t * n;

	if ((iter == NULL) || (key == NULL) || (value == NULL)) return -1;

	if (iter->node == NULL)
	{
		for (n = iter->tree->root; n != NULL; n = n->left)
			if (n->left == NULL) break;
		iter->node = n;
	}
	else
	{
		n = c_avl_node_next(iter->node);
	}

	if (n == NULL) return -1;

	iter->node = n;
	*key = n->key;
	*value = n->value;

	return 0;
} /* int c_avl_iterator_next */

int c_avl_iterator_prev(c_avl_iterator_t * iter, void ** key, void ** value)
{
	c_avl_node_t * n;

	if ((iter == NULL) || (key == NULL) || (value == NULL)) return -1;

	if (iter->node == NULL)
	{
		for (n = iter->tree->root; n != NULL; n = n->left)
			if (n->right == NULL) break;
		iter->node = n;
	}
	else
	{
		n = c_avl_node_prev(iter->node);
	}

	if (n == NULL) return -1;

	iter->node = n;
	*key = n->key;
	*value = n->value;

	return 0;
} /* int c_avl_iterator_prev */

void c_avl_iterator_destroy(c_avl_iterator_t * iter) { free(iter); }

int c_avl_size(c_avl_tree_t * t)
{
	if (t == NULL) return 0;
	return t->size;
}
