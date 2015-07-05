/* adlist.c - A generic doubly linked list implementation
 *
 * Copyright (c) 2006-2010, Salvatore Sanfilippo <antirez at gmail dot com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Redis nor the names of its contributors may be used
 *     to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */


#include <stdlib.h>
#include "adlist.h"
#include "zmalloc.h"

/* Create a new list. The created list can be freed with
 * AlFreeList(), but private value of every node need to be freed
 * by the user before to call AlFreeList().
 *
 * On error, NULL is returned. Otherwise the pointer to the new list. */

/*
*
* 创建链表
*
*/
list *listCreate(void)
{
    struct list *list;

    if ((list = zmalloc(sizeof(*list))) == NULL)
        return NULL;
    list->head = list->tail = NULL;
    list->len = 0;
    list->dup = NULL;
    list->free = NULL;
    list->match = NULL;
    return list;
}

/* Free the whole list.
 *
 * This function can't fail. */

/*
*
* 释放链表的资源
*
*/
void listRelease(list *list)
{
    unsigned long len;
    listNode *current, *next;

    current = list->head;   // 头节点 ( head )
    len = list->len;        // 链表长度
    while(len--) {
        next = current->next; // 记录下一个节点
        if (list->free) list->free(current->value);  // 释放节点数据 (节点的数据是一个指针)
        zfree(current);       // 释放当前节点
        current = next;       // 更新节点 
    }
    zfree(list);              // 释放头节点 
}

/* Add a new node to the list, to head, containing the specified 'value'
 * pointer as value.
 *
 * On error, NULL is returned and no operation is performed (i.e. the
 * list remains unaltered).
 * On success the 'list' pointer you pass to the function is returned. */

/*
*
* 添加节点 (头插法)
*
*/
list *listAddNodeHead(list *list, void *value)
{
    listNode *node;

    if ((node = zmalloc(sizeof(*node))) == NULL)
        return NULL;
    node->value = value;
    if (list->len == 0) {                 // 链表为空
        list->head = list->tail = node;
        node->prev = node->next = NULL;
    } else {
        node->prev = NULL;                
        node->next = list->head;           
        list->head->prev = node;
        list->head = node;                // 更新头节点
    }
    list->len++;
    return list;
}

/* Add a new node to the list, to tail, containing the specified 'value'
 * pointer as value.
 *
 * On error, NULL is returned and no operation is performed (i.e. the
 * list remains unaltered).
 * On success the 'list' pointer you pass to the function is returned. */

/*
*
* 添加节点 (尾插法)
*
*/

list *listAddNodeTail(list *list, void *value)
{
    listNode *node;

    if ((node = zmalloc(sizeof(*node))) == NULL)
        return NULL;
    node->value = value;
    if (list->len == 0) {                      // 链表为空
        list->head = list->tail = node;
        node->prev = node->next = NULL;
    } else {
        node->prev = list->tail;
        node->next = NULL;
        list->tail->next = node;
        list->tail = node;
    }
    list->len++;
    return list;
}

/*
*
* after 为 true 时,在 old_node 后面插入新节点 (有可能更新链表的尾节点)
*
* after 为 false 时,在 old_node 前面插入新节点 (有可能更新链表的头节点)
*/
list *listInsertNode(list *list, listNode *old_node, void *value, int after) {
    listNode *node;

    if ((node = zmalloc(sizeof(*node))) == NULL)
        return NULL;
    node->value = value;
    if (after) {                                   // after 为 true 
        node->prev = old_node;                     // 在 old_node 后面插入节点
        node->next = old_node->next;
        if (list->tail == old_node) {           
            list->tail = node;                     // 更新尾节点
        }
    } else {                                       // after 为 false
        node->next = old_node;                     // 在 old_node 前面插入节点
        node->prev = old_node->prev;
        if (list->head == old_node) {
            list->head = node;                     // 更新头节点
        }
    }
    if (node->prev != NULL) {
        node->prev->next = node;
    }
    if (node->next != NULL) {
        node->next->prev = node;
    }
    list->len++;
    return list;
}

/* Remove the specified node from the specified list.
 * It's up to the caller to free the private value of the node.
 *
 * This function can't fail. */

/*
*
* 删除指定节点
*
*/
void listDelNode(list *list, listNode *node)
{
    if (node->prev)                          // node 前面有节点
        node->prev->next = node->next;
    else                                     // 否则是头节点
        list->head = node->next;
    if (node->next)                          // node 后面有节点
        node->next->prev = node->prev;       
    else
        list->tail = node->prev;             // 否则是尾节点
    if (list->free) list->free(node->value); // 释放 node 中的数据域(指针)
    zfree(node);                             // 释放节点 
    list->len--;
}

/* Returns a list iterator 'iter'. After the initialization every
 * call to listNext() will return the next element of the list.
 *
 * This function can't fail. */

/*
*
* 获取指向链表的迭代器
* 
* direction 指示迭代器的位置 ( 头 或者 尾 )
*
*/
listIter *listGetIterator(list *list, int direction)
{
    listIter *iter;

    if ((iter = zmalloc(sizeof(*iter))) == NULL) return NULL;
    if (direction == AL_START_HEAD)
        iter->next = list->head;          // 指向头节点
    else
        iter->next = list->tail;          // 指向尾节点
    iter->direction = direction;
    return iter;
}

/* Release the iterator memory */

/*
*
* 释放迭代器 
*
*/
void listReleaseIterator(listIter *iter) {
    zfree(iter);
}

/* Create an iterator in the list private iterator structure */

/*
*
* 将迭代器重新指向链表头节点
*
*/
void listRewind(list *list, listIter *li) {
    li->next = list->head;
    li->direction = AL_START_HEAD;
}

/*
*
* 将迭代器重新指向链表尾节点
*
*/
void listRewindTail(list *list, listIter *li) {
    li->next = list->tail;
    li->direction = AL_START_TAIL;
}

/* Return the next element of an iterator.
 * It's valid to remove the currently returned element using
 * listDelNode(), but not to remove other elements.
 *
 * The function returns a pointer to the next element of the list,
 * or NULL if there are no more elements, so the classical usage patter
 * is:
 *
 * iter = listGetIterator(list,<direction>);
 * while ((node = listNext(iter)) != NULL) {
 *     doSomethingWith(listNodeValue(node));
 * }
 *
 * */

/*
*
* 迭代器的移动
* 
* 根据迭代器的方向不同而 前向 或者 后向 移动
*/
listNode *listNext(listIter *iter)
{
    listNode *current = iter->next;

    if (current != NULL) {
        if (iter->direction == AL_START_HEAD)
            iter->next = current->next;
        else
            iter->next = current->prev;
    }
    return current;           // iter 已经到了 头节点 或者 尾节点,返回 NULL 
}

/* Duplicate the whole list. On out of memory NULL is returned.
 * On success a copy of the original list is returned.
 *
 * The 'Dup' method set with listSetDupMethod() function is used
 * to copy the node value. Otherwise the same pointer value of
 * the original node is used as value of the copied node.
 *
 * The original list both on success or error is never modified. */

/*
*
* 复制链表 orig
*
*/
list *listDup(list *orig)
{
    list *copy;
    listIter *iter;
    listNode *node;

    if ((copy = listCreate()) == NULL)           // 生成 ( struct )list 节点
        return NULL;
    copy->dup = orig->dup;
    copy->free = orig->free;
    copy->match = orig->match;                    // 复制函数指针
    iter = listGetIterator(orig, AL_START_HEAD);  // 获取指向 头节点 的迭代器
    while((node = listNext(iter)) != NULL) {
        void *value;

        if (copy->dup) {
            value = copy->dup(node->value);
            if (value == NULL) {
                listRelease(copy);
                listReleaseIterator(iter);
                return NULL;
            }
        } else
            value = node->value;                     // 单纯的指针赋值 (注意:释放的时候要小心)
        if (listAddNodeTail(copy, value) == NULL) {  // 尾插法
            listRelease(copy);
            listReleaseIterator(iter);
            return NULL;
        }
    }
    listReleaseIterator(iter);                       // 释放迭代器
    return copy;
}

/* Search the list for a node matching a given key.
 * The match is performed using the 'match' method
 * set with listSetMatchMethod(). If no 'match' method
 * is set, the 'value' pointer of every node is directly
 * compared with the 'key' pointer.
 *
 * On success the first matching node pointer is returned
 * (search starts from head). If no matching node exists
 * NULL is returned. */

/*
*
* 链表中查找指定 key
*
* 未找到返回 NULL 
*/
listNode *listSearchKey(list *list, void *key)
{
    listIter *iter;
    listNode *node;

    iter = listGetIterator(list, AL_START_HEAD);
    while((node = listNext(iter)) != NULL) {
        if (list->match) {
            if (list->match(node->value, key)) {
                listReleaseIterator(iter);
                return node;
            }
        } else {
            if (key == node->value) {
                listReleaseIterator(iter);
                return node;
            }
        }
    }
    listReleaseIterator(iter);
    return NULL;                                   
}

/* Return the element at the specified zero-based index
 * where 0 is the head, 1 is the element next to head
 * and so on. Negative integers are used in order to count
 * from the tail, -1 is the last element, -2 the penultimate
 * and so on. If the index is out of range NULL is returned. */

/*
*
* 返回指定序号的节点指针
*
* index<0 从后往前计算 第 index 个节点
*
* index>0 从前往后计算 第 index+1 个节点
* 
*/
listNode *listIndex(list *list, long index) {
    listNode *n;

    if (index < 0) {                       // -1 代表尾节点 
        index = (-index)-1;                // 跳 ( -index-1 ) 下
        n = list->tail;
        while(index-- && n) n = n->prev;
    } else {
        n = list->head;                   // head 的节点序号是从 0 开始
        while(index-- && n) n = n->next;  // 跳 index 下
    }                                     // 第 index 的节点
    return n;
}

/* Rotate the list removing the tail node and inserting it to the head. */

/*
*
* 将链表的尾节点旋转到头节点
*
*/
void listRotate(list *list) {
    listNode *tail = list->tail;

    if (listLength(list) <= 1) return;

    /* Detach current tail */
    list->tail = tail->prev;
    list->tail->next = NULL;
    /* Move it as head */
    list->head->prev = tail;
    tail->prev = NULL;
    tail->next = list->head;
    list->head = tail;
}
