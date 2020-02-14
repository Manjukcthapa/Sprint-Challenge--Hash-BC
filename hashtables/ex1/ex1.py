#  Hint:  You may not need all of these.  Remove the unused functions.
from hashtables import (HashTable,
                        hash_table_insert,
                        hash_table_remove,
                        hash_table_retrieve,
                        hash_table_resize)


def get_indices_of_item_weights(weights, length, limit):
    ht = HashTable(16)

    for i in range(length): # insert weights with the index onto hashtable -- insert
        hash_table_insert(ht, weights[i], i)
    # subtract weights from hashtable limit
    for i in range(length):
        value = hash_table_retrieve(ht, limit - weights[i]) # limit - index weights
        # if the value isn't none...
        if value is not None:
            # return key, value in acsending order
            if i > value: 
        # higher valued index should be placed in the "zeroth" index and the smaller index
        #  should be placed in the "first" index
             return (i, value)
            else: # if the index isn't larger then return value first.
                return (value, i)

    return None


def print_answer(answer):
    if answer is not None:
        print(str(answer[0] + " " + answer[1]))
    else:
        print("None")
