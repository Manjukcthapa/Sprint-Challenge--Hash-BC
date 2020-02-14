from hashtables import (HashTable,
                        hash_table_insert,
                        hash_table_remove,
                        hash_table_retrieve,
                        hash_table_resize)


class Ticket:
    def __init__(self, source, destination):
        self.source = source
        self.destination = destination


def reconstruct_trip(tickets, length):
    hashtable = HashTable(length)
    route = [None] * length

    # here we are inserting a hash per the length of the tickets so here
    #  for example we have 5 tickets and so we insert the length of 
    # the ticket list, source ,and destination
    for t in tickets:
   # we are starting the sequence so we can work with changing it around      
        hash_table_insert(hashtable, t.source, t.destination)
# The first ticket must have NONE as the source
    current_location = "NONE"
# so have to loop as long as the length of the list of tickets.   
    for i in range(length):
# gets the source of the last ticket and set it to the next route
        route[i] = hash_table_retrieve(hashtable, current_location)
# the list above labled "route" has a list of a bunch of
#  NONE's so we change FIRST index with the current location which is our head
        current_location = route[i]
# function should output an array of strings with the entire route of a trip

    return route 
  




