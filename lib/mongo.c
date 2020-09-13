#include <bson/bson.h>
#include <mongoc/mongoc.h>
#include <stdio.h>
#include <strings.h>

#include "common.h"
#include "mongo.h"

void mongo_search(char *scenario_name){
  char *ip = "localhost";
  char *port = "27017";
  char *dbname = "mydb";
  char *collname = "mycoll";
  printf("test input\n");

  mongoc_client_t *client;
  mongoc_collection_t *collection;
  mongoc_cursor_t *cursor;
  const bson_t *doc;
  bson_t *query;
  char *str;

  char *client_name;
  int size = strlen("mongodb://") + strlen(ip) + strlen(":") + strlen(port);
  client_name = malloc(size);
  snprintf(client_name, size+1, "mongodb://%s:%s", ip, port);

  mongoc_init ();
  client = mongoc_client_new(client_name);
  free(client_name);
  collection = mongoc_client_get_collection (client, dbname, collname);
  query = bson_new ();
  BSON_APPEND_UTF8 (query, "hello", "test");


  cursor = mongoc_collection_find_with_opts (collection, query, NULL, NULL);

  while (mongoc_cursor_next (cursor, &doc)) {
     str = bson_as_canonical_extended_json (doc, NULL);
     printf ("%s\n", str);
     bson_free (str);
  }

  bson_destroy (query);
  mongoc_cursor_destroy (cursor);
  mongoc_collection_destroy (collection);
  mongoc_client_destroy (client);
  mongoc_cleanup ();

}
