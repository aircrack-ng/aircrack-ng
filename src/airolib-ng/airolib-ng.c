/*
 *  A tool to compute and manage PBKDF2 values as used in WPA-PSK and WPA2-PSK
 *
 *  Copyright (C) 2007-2009 ebfe
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 *
 *  In addition, as a special exception, the copyright holders give
 *  permission to link the code of portions of this program with the
 *  OpenSSL library under certain conditions as described in each
 *  individual source file, and distribute linked combinations
 *  including the two.
 *  You must obey the GNU General Public License in all respects
 *  for all of the code used other than OpenSSL. *  If you modify
 *  file(s) with this exception, you may extend this exception to your
 *  version of the file(s), but you are not obligated to do so. *  If you
 *  do not wish to do so, delete this exception statement from your
 *  version. *  If you delete this exception statement from all source
 *  files in the program, then also delete it here.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <sqlite3.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>
#include <signal.h>

#include "aircrack-ng/defs.h"
#include "aircrack-ng/cowpatty/cowpatty.h"
#include "aircrack-ng/crypto/crypto.h"
#ifdef HAVE_REGEXP
#include <regex.h>
#endif
#include "aircrack-ng/version.h"

#define IMPORT_ESSID "essid"
#define EXPORT_ESSID IMPORT_ESSID
#define IMPORT_PASSWD "passwd"
#define IMPORT_PASSWD_ALT "password"
#define IMPORT_COWPATTY "cowpatty"
#define EXPORT_COWPATTY IMPORT_COWPATTY

static int exit_airolib;

static void print_help(const char * msg)
{
	char * version_info
		= getVersion("Airolib-ng", _MAJ, _MIN, _SUB_MIN, _REVISION, _BETA, _RC);
	printf("\n"
		   "  %s - (C) 2007, 2008, 2009 ebfe\n"
		   "  https://www.aircrack-ng.org\n"
		   "\n"
		   "  Usage: airolib-ng <database> <operation> [options]\n"
		   "\n"
		   "  Operations:\n"
		   "\n"
		   "       --stats        : Output information about the database.\n"
		   "       --sql <sql>    : Execute specified SQL statement.\n"
		   "       --clean [all]  : Clean the database from old junk. 'all' "
		   "will also \n"
		   "                        reduce filesize if possible and run an "
		   "integrity check.\n"
		   "       --batch        : Start batch-processing all combinations of "
		   "ESSIDs\n"
		   "                        and passwords.\n"
		   "       --verify [all] : Verify a set of randomly chosen PMKs.\n"
		   "                        If 'all' is given, all invalid PMK will be "
		   "deleted.\n"
		   "\n"
		   "       --import [%s|%s] <file>   :\n"
		   "                        Import a text file as a list of ESSIDs or "
		   "passwords.\n"
		   "       --import %s <file>         :\n"
		   "                        Import a cowpatty file.\n"
		   "\n"
		   "       --export %s <%s> <file> :\n"
		   "                        Export to a cowpatty file.\n"
		   "\n",
		   version_info,
		   IMPORT_ESSID,
		   IMPORT_PASSWD,
		   IMPORT_COWPATTY,
		   EXPORT_COWPATTY,
		   EXPORT_ESSID);
	free(version_info);

	if (msg && *msg != '\0')
	{
		printf("%s", msg);
		puts("");
	}
}

static void sighandler(int signum)
{
#if ((defined(__INTEL_COMPILER) || defined(__ICC)) && defined(DO_PGO_DUMP))
	_PGOPTI_Prof_Dump();
#endif
#if !defined(__CYGWIN__)
	// We can't call this on cygwin or we will sometimes end up
	// having all our threads die with exit code 35584 fairly reproducible
	// at around 2.5-3% of runs
	signal(signum, sighandler);
#endif

	if (signum == SIGQUIT) exit_airolib = 1;

	if (signum == SIGTERM) exit_airolib = 1;

	if (signum == SIGINT) exit_airolib = 1;
}

static void sql_error(sqlite3 * db)
{
	REQUIRE(db != NULL);

	fprintf(stderr, "Database error: %s\n", sqlite3_errmsg(db));
}

static int sql_exec_cb(sqlite3 * db,
					   const char * sql,
					   int (*callback)(void *, int, char **, char **),
					   void * cb_arg)
{
	REQUIRE(db != NULL);
	REQUIRE(sql != NULL);

#ifdef SQL_DEBUG
	printf(sql);
	printf("\n");
	fflush(stdout);
#endif

	int rc;
	char * zErrMsg = 0;
	char looper[4] = {'|', '/', '-', '\\'};
	int looperc = 0;
	int waited = 0;

	while (1)
	{
		rc = sqlite3_exec(db, sql, callback, cb_arg, &zErrMsg);
		if (rc == SQLITE_LOCKED || rc == SQLITE_BUSY)
		{
			fprintf(stdout,
					"Database is locked or busy. Waiting %is ... %1c    \r",
					++waited,
					looper[looperc++ % sizeof(looper)]);
			fflush(stdout);
			sleep(1);
			if (zErrMsg)
			{
				sqlite3_free(zErrMsg);
				zErrMsg = NULL;
			}
		}
		else
		{
			if (rc != SQLITE_OK)
			{
				fprintf(stderr, "SQL error. %s\n", zErrMsg);
			}
			if (waited != 0) printf("\n\n");
			if (zErrMsg)
			{
				sqlite3_free(zErrMsg);
				zErrMsg = NULL;
			}
			return (rc);
		}
	}
}

// execute sql fast and hard.
static int sql_exec(sqlite3 * db, const char * sql)
{
	REQUIRE(db != NULL);
	REQUIRE(sql != NULL);

	return (sql_exec_cb(db, sql, 0, 0));
}

// wrapper for sqlite3_step which retries executing statements if the db returns
// SQLITE_BUSY or SQLITE_LOCKED
static int sql_step(sqlite3_stmt * stmt, int wait)
{
	REQUIRE(stmt != NULL);

	int rc;
	char looper[4] = {'|', '/', '-', '\\'};
	int looperc = 0;
	int waited = 0;

	while (1)
	{
		rc = sqlite3_step(stmt);
		if (rc == SQLITE_LOCKED || rc == SQLITE_BUSY)
		{
			if (wait != 0)
			{
				fprintf(stdout,
						"Database is locked or busy. Waiting %is ... %1c    \r",
						++waited,
						looper[looperc]);
				fflush(stdout);
				wait--;
				looperc = looperc + 1 % sizeof(looper);
				sleep(1);
			}
			else
			{
				fprintf(stderr,
						"Database was locked or busy while getting "
						"results. I've given up.\n");
				return (rc);
			}
		}
		else
		{
			if (waited != 0) printf("\n\n");
			return (rc);
		}
	}
}

// wrapper for sqlite3_prepare_v2 which retries creating statements if the db
// returns SQLITE_BUSY or SQLITE_LOCKED
static int
sql_prepare(sqlite3 * db, const char * sql, sqlite3_stmt ** ppStmt, int wait)
{
	REQUIRE(db != NULL);
	REQUIRE(sql != NULL);

#ifdef SQL_DEBUG
	printf(sql);
	printf("\n");
	fflush(stdout);
#endif

	int rc;
	char looper[4] = {'|', '/', '-', '\\'};
	int looperc = 0;
	int waited = 0;

	while (1)
	{
		rc = sqlite3_prepare_v2(db, sql, -1, ppStmt, NULL);
		if (rc == SQLITE_LOCKED || rc == SQLITE_BUSY)
		{
			if (wait != 0)
			{
				fprintf(stdout,
						"Database is locked or busy. Waiting %is ... %1c    \r",
						++waited,
						looper[looperc]);
				fflush(stdout);
				wait--;
				looperc = looperc + 1 % sizeof(looper);
				sleep(1);
			}
			else
			{
				fprintf(stderr,
						"Database was locked or busy while creating "
						"statement. I've given up.\n");
				return (rc);
			}
		}
		else
		{
			if (waited != 0) printf("\n\n");
			return (rc);
		}
	}
}

// generic function to dump a resultset including column names to stdout
static int stmt_stdout(sqlite3_stmt * stmt, int * rowcount)
{
	REQUIRE(stmt != NULL);

	int ccount;
	int rcount = 0;
	int rc;

	if ((ccount = sqlite3_column_count(stmt)) == 0)
	{
		return (sql_step(stmt, 0));
	}

	int i = 0;
	do
	{
		printf("%s", sqlite3_column_name(stmt, i++));
		if (i < ccount) printf("\t");
	} while (i < ccount);
	printf("\n");

	while ((rc = sql_step(stmt, 0)) == SQLITE_ROW)
	{
		i = 0;
		rcount++;
		do
		{
			printf("%s", (char *) sqlite3_column_text(stmt, i++));
			if (i < ccount) printf("\t");
		} while (i < ccount);
		printf("\n");
	}

	if (rowcount != NULL) *rowcount = rcount;

	return (rc);
}

// generic function to dump the output of a sql statement to stdout.
// will return sqlite error codes but also handle (read: ignore) them itself
static int sql_stdout(sqlite3 * db, const char * sql, int * rowcount)
{
	REQUIRE(db != NULL);
	REQUIRE(sql != NULL);

	int rc;
	sqlite3_stmt * stmt;

	rc = sql_prepare(db, sql, &stmt, -1);
	if (rc != SQLITE_OK)
	{
		sql_error(db);
		return (rc);
	}

	rc = stmt_stdout(stmt, rowcount);
	sqlite3_finalize(stmt);

	if (rc == SQLITE_DONE)
	{
		if (sqlite3_changes(db) > 0)
			fprintf(
				stdout, "Query done. %i rows affected.", sqlite3_changes(db));
	}
	else
	{
		sql_error(db);
	}

	printf("\n");
	return (rc);
}

// retrieve a single int value using a sql query.
// returns 0 if something goes wrong. beware! create your own statement if you
// need error handling.
static int query_int(sqlite3 * db, const char * sql)
{
	REQUIRE(db != NULL);

	sqlite3_stmt * stmt;
	int rc;
	int ret;

	rc = sql_prepare(db, sql, &stmt, -1);
	if (rc != SQLITE_OK || stmt == 0 || sqlite3_column_count(stmt) == 0)
	{
		sql_error(db);
		ret = 0;
	}
	else
	{
		rc = sql_step(stmt, -1);
		if (rc == SQLITE_ROW)
		{
			ret = sqlite3_column_int(stmt, 0);
		}
		else
		{
#ifdef SQL_DEBUG
			printf(
				"DEBUG: query_int() returns with sql_step() != SQLITE_ROW\n");
#endif
			ret = 0;
		}
	}

	sqlite3_finalize(stmt);

	return (ret);
}

// throw some statistics about the db to stdout.
// if precise!=0 the stats will be queried nail by nail which can be slow
static void show_stats(sqlite3 * db, int precise)
{
	REQUIRE(db != NULL);

	sql_exec(db, "BEGIN;");

	int essids = query_int(db, "SELECT COUNT(*) FROM essid;");
	int passwds = query_int(db, "SELECT COUNT(*) FROM passwd;");
	int done;

	if (precise != 0)
	{
		printf("Determining precise statistics may be slow...\n");
		done = query_int(db,
						 "SELECT COUNT(*) FROM essid,passwd INNER JOIN pmk "
						 "ON pmk.essid_id = essid.essid_id AND "
						 "pmk.passwd_id = passwd.passwd_id");
	}
	else
	{
		done = query_int(db, "SELECT COUNT(*) FROM pmk;");
	}

	fprintf(stdout,
			"There are %i ESSIDs and %i passwords in the database. %i out of "
			"%i possible combinations have been computed (%g%%).\n\n",
			essids,
			passwds,
			done,
			essids * passwds,
			essids * passwds > 0 ? ((double) done * 100) / (essids * passwds)
								 : 0);

	if (precise != 0)
	{
		sql_stdout(db,
				   "select essid.essid AS ESSID, essid.prio AS Priority, "
				   "round(count(pmk.essid_id) * 100.0 / count(*),2) AS Done "
				   "from essid,passwd left join pmk on pmk.essid_id = "
				   "essid.essid_id and pmk.passwd_id = passwd.passwd_id group "
				   "by essid.essid_id;",
				   0);
	}
	else
	{
		sql_stdout(db,
				   "SELECT essid.essid AS ESSID, essid.prio AS Priority, "
				   "ROUND(COUNT(pmk.essid_id) * 100.0 / (SELECT COUNT(*) FROM "
				   "passwd),2) AS Done FROM essid LEFT JOIN pmk ON "
				   "pmk.essid_id = essid.essid_id GROUP BY essid.essid_id;",
				   0);
	}

	sql_exec(db, "COMMIT;");
}

/*
batch-process all combinations of ESSIDs and PASSWDs. this function may be
called
only once per db at the same time, yet multiple processes can batch-process a
single db.
don't modify this function's layout or it's queries without carefully
considering speed, efficiency and concurrency.
*/
static void batch_process(sqlite3 * db)
{
	REQUIRE(db != NULL);

	int rc;
	int cur_essid = 0;
	struct timeval starttime;
	struct timeval curtime;
	int rowcount = 0;
	char * sql;

	gettimeofday(&starttime, NULL);

	if (sql_exec(db,
				 "CREATE TEMPORARY TABLE temp.buffer (wb_id integer, "
				 "essid_id integer, passwd_id integer, essid text, passwd "
				 "text, pmk blob);")
		!= SQLITE_OK)
	{
		fprintf(stderr, "Failed to create buffer for batch processing.\n");
		return;
	}

	printf("Batch processing ...\n");

	// may fail - that's ok
	cur_essid = query_int(db, "SELECT essid_id FROM workbench LIMIT 1;");

	while (!exit_airolib)
	{
		// loop over everything
		do
		{
			// loop over ESSID
			do
			{
				// loop over workbench
				sql_exec(db, "DELETE FROM temp.buffer;");
				// select some work from the workbench into our own buffer
				// move lockid ahead so other clients won't get those rows any
				// time soon
				sql_exec(db, "BEGIN EXCLUSIVE;");
				sql_exec(db,
						 "INSERT INTO temp.buffer "
						 "(wb_id,essid_id,passwd_id,essid,passwd) SELECT "
						 "wb_id, "
						 "essid.essid_id,passwd.passwd_id,essid,passwd "
						 "FROM workbench CROSS JOIN essid ON "
						 "essid.essid_id = workbench.essid_id CROSS JOIN "
						 "passwd ON passwd.passwd_id = workbench.passwd_id "
						 "ORDER BY lockid LIMIT 5000;");
				sql_exec(db,
						 "UPDATE workbench SET lockid=lockid+1 WHERE wb_id "
						 "IN (SELECT wb_id FROM buffer);");
				sql_exec(db, "COMMIT;");

				rc = query_int(db, "SELECT COUNT(*) FROM buffer;");
				if (rc > 0)
				{
					// now calculate all the PMKs with a single statement.
					// remember the update won't lock the db
					sql_exec(db,
							 "UPDATE temp.buffer SET pmk = PMK(essid,passwd);");

					// commit work and delete package from workbench
					sql_exec(db, "BEGIN EXCLUSIVE;");
					sql_exec(db,
							 "INSERT OR IGNORE INTO pmk "
							 "(essid_id,passwd_id,pmk) SELECT "
							 "essid_id,passwd_id,pmk FROM temp.buffer");
					sql_exec(db,
							 "DELETE FROM workbench WHERE wb_id IN (SELECT "
							 "wb_id FROM buffer);");
					sql_exec(db, "COMMIT;");

					rowcount += rc;
					gettimeofday(&curtime, NULL);
					int timediff = curtime.tv_sec - starttime.tv_sec;
					fprintf(stdout,
							"\rComputed %i PMK in %i seconds (%i PMK/s, %i in "
							"buffer)\n",
							rowcount,
							timediff,
							timediff > 0 ? rowcount / timediff : rowcount,
							query_int(db, "SELECT COUNT(*) FROM workbench;"));
					fflush(stdout);
				}
			} while (rc > 0 && !exit_airolib);
			sql = sqlite3_mprintf(
				"INSERT OR IGNORE INTO workbench (essid_id,passwd_id) SELECT "
				"essid.essid_id,passwd.passwd_id FROM passwd CROSS JOIN essid "
				"LEFT JOIN pmk ON pmk.essid_id = essid.essid_id AND "
				"pmk.passwd_id = passwd.passwd_id WHERE essid.essid_id = %i "
				"AND pmk.essid_id IS NULL LIMIT 250000;",
				cur_essid);
			sql_exec(db, sql);
			sqlite3_free(sql);
		} while (!exit_airolib
				 && query_int(db,
							  "SELECT COUNT(*) FROM workbench INNER JOIN "
							  "essid ON essid.essid_id = "
							  "workbench.essid_id INNER JOIN passwd ON "
							  "passwd.passwd_id = workbench.passwd_id;")
						> 0);

		cur_essid = query_int(
			db,
			"SELECT essid.essid_id FROM essid LEFT JOIN pmk USING "
			"(essid_id) WHERE VERIFY_ESSID(essid.essid) == 0 GROUP BY "
			"essid.essid_id HAVING COUNT(pmk.essid_id) < (SELECT COUNT(*) "
			"FROM passwd) ORDER BY essid.prio,COUNT(pmk.essid_id),RANDOM() "
			"LIMIT 1;");
		if (cur_essid == 0)
		{
			printf("All ESSID processed.\n\n");
			sqlite3_close(db);
			exit(EXIT_SUCCESS);
		}
	}

	// never reached
	sql_exec(db, "DROP TABLE temp.buffer;");
}

// Verify an ESSID. Returns 1 if ESSID is invalid.
// TODO More things to verify? Invalid chars?
static int verify_essid(char * const essid)
{
	const size_t essid_len = essid ? strlen(essid) : 0;

	return (essid_len < 1 || essid_len > 32);
}

// sql function which checks a given ESSID
static void
sql_verify_essid(sqlite3_context * context, int argc, sqlite3_value ** values)
{
	char * essid = (char *) sqlite3_value_text(values[0]);
	if (argc != 1 || essid == 0)
	{
		fprintf(stderr,
				"SQL function VERIFY_ESSID called with invalid arguments");
		return;
	}
	sqlite3_result_int(context, verify_essid(essid));
}

static int verify_passwd(char * const passwd)
{
	const size_t passwd_len = passwd ? strlen(passwd) : 0;

	return (passwd_len < 8 || passwd_len > 63);
}

static void
sql_verify_passwd(sqlite3_context * context, int argc, sqlite3_value ** values)
{
	char * passwd = (char *) sqlite3_value_text(values[0]);
	if (argc != 1 || passwd == 0)
	{
		fprintf(stderr,
				"SQL function VERIFY_PASSWD called with invalid arguments");
		return;
	}
	sqlite3_result_int(context, verify_passwd(passwd));
}

// clean the db, analyze, maybe vacuum and check
static void vacuum(sqlite3 * db, int deep)
{
	printf("Deleting invalid ESSIDs and passwords...\n");
	sql_exec(db, "DELETE FROM essid WHERE VERIFY_ESSID(essid) != 0;");
	sql_exec(db, "DELETE FROM passwd WHERE VERIFY_PASSWD(passwd) != 0");
	printf("Deleting unreferenced PMKs...\n");
	sql_exec(
		db,
		"DELETE FROM pmk WHERE essid_id NOT IN (SELECT essid_id FROM essid)");
	sql_exec(db,
			 "DELETE FROM pmk WHERE passwd_id NOT IN (SELECT passwd_id "
			 "FROM passwd)");

	printf("Analysing index structure...\n");
	sql_exec(db, "ANALYZE;");
	if (deep != 0)
	{
		printf("Vacuum-cleaning the database. This could take a while...\n");
		sql_exec(db, "VACUUM;");
		printf("Checking database integrity...\n");
		sql_stdout(db, "PRAGMA integrity_check;", 0);
	}
	printf("Done.\n");
}

// verify PMKs. If complete==1 we check all PMKs
// returns 0 if ok, !=0 otherwise
static void verify(sqlite3 * db, int complete)
{
	if (complete != 1)
	{
		printf("Checking ~10 000 randomly chosen PMKs...\n");
		// this is faster than 'order by random()'. we need the subquery to
		// trick the optimizer...
		sql_stdout(db,
				   "select s.essid AS ESSID, COUNT(*) AS CHECKED, CASE WHEN "
				   "MIN(s.pmk == PMK(essid,passwd)) == 0 THEN 'FAILED' ELSE "
				   "'OK' END AS STATUS FROM (select distinct essid,passwd,pmk "
				   "FROM pmk INNER JOIN passwd ON passwd.passwd_id = "
				   "pmk.passwd_id INNER JOIN essid ON essid.essid_id = "
				   "pmk.essid_id WHERE abs(random() % (select count(*) from "
				   "pmk)) < 10000) AS s GROUP BY s.essid;",
				   0);
	}
	else
	{
		printf("Checking all PMKs. This could take a while...\n");
		sql_stdout(db,
				   "select essid AS ESSID,passwd AS PASSWORD,HEX(pmk) AS "
				   "PMK_DB, HEX(PMK(essid,passwd)) AS CORRECT FROM pmk INNER "
				   "JOIN passwd ON passwd.passwd_id = pmk.passwd_id INNER JOIN "
				   "essid ON essid.essid_id = pmk.essid_id WHERE pmk.pmk != "
				   "PMK(essid,passwd);",
				   0);
	}
}

// callback for export_cowpatty. takes the passwd and pmk from the query and
// writes another fileentry.
static int
sql_exportcow(void * arg, int ccount, char ** values, char ** columnnames)
{
	REQUIRE(arg != NULL);
	UNUSED_PARAM(columnnames);

	FILE * f = (FILE *) arg;
	struct hashdb_rec rec;
	if (ccount != 2 || values[0] == NULL || values[1] == NULL
		|| fileno(f) == -1)
	{
		printf("Illegal call to sql_exportcow.\n");
		return (-1);
	}

	char * passwd = (char *) values[0];

	memcpy(rec.pmk, values[1], sizeof(rec.pmk));
	rec.rec_size = strlen(passwd) + sizeof(rec.pmk) + sizeof(rec.rec_size);

	int rc = fwrite(&rec.rec_size, sizeof(rec.rec_size), 1, f);
	rc += fwrite(passwd, strlen(passwd), 1, f);
	rc += fwrite(rec.pmk, sizeof(rec.pmk), 1, f);
	if (rc != 3)
	{
		printf("Error while writing to export file. Query aborted...\n");
		return (1);
	}
	fflush(f);
	return (0);
}

// export to a cowpatty file
static void export_cowpatty(sqlite3 * db, char * essid, char * filename)
{
	struct hashdb_head filehead;
	memset(&filehead, 0, sizeof(filehead));
	FILE * f = NULL;
	size_t essid_len;
	int fd;

	if (essid == NULL)
	{
		printf("Invalid SSID (NULL).\n");
		return;
	}

	if (filename == NULL || *filename == '\0')
	{
		printf("Invalid filename (NULL)");
		return;
	}

	essid_len = strlen(essid);
	if (essid_len == 0 || essid_len > sizeof(filehead.ssid))
	{
		printf("Invalid SSID (NULL or > %zu chars).\n", sizeof(filehead.ssid));
		return;
	}

	// ensure that the essid is found in the db and has at least one entry in
	// the pmk table.
	char * sql = sqlite3_mprintf(
		"SELECT COUNT(*) FROM (SELECT passwd, pmk FROM essid,passwd INNER JOIN "
		"pmk ON pmk.passwd_id = passwd.passwd_id AND pmk.essid_id = "
		"essid.essid_id WHERE essid.essid = '%q' LIMIT 1);",
		essid);
	int rc = query_int(db, sql);
	sqlite3_free(sql);
	if (rc == 0)
	{
		printf("There is no such ESSID in the database or there are no PMKs "
			   "for it.\n");
		return;
	}

	if ((fd = open(filename, O_WRONLY | O_CREAT | O_EXCL, 0666)) >= 0)
	{
		f = fdopen(fd, "w");
	}
	else
	{
		printf("The file already exists and I won't overwrite it.\n");
		return;
	}

	if (f == NULL)
	{
		printf("Failed to open export file for writing.\n");
		return;
	}

	memcpy(filehead.ssid, essid, essid_len);
	filehead.ssidlen = essid_len;
	filehead.magic = GENPMKMAGIC;
	if (fwrite(&filehead, sizeof(filehead), 1, f) != 1)
	{
		printf("Failed to write header to coWPAtty hash DB file.\n");
		fclose(f);
		return;
	}

	// as we have an open filehandle, we now query the db to return passwds and
	// associated PMKs for that essid. we pass the filehandle to a callback
	// function which will write the rows to the file.
	sql = sqlite3_mprintf(
		"SELECT passwd, pmk FROM essid,passwd INNER JOIN pmk "
		"ON pmk.passwd_id = passwd.passwd_id AND pmk.essid_id "
		"= essid.essid_id WHERE essid.essid = '%q'",
		essid);
	printf("Exporting...\n");
	rc = sql_exec_cb(db, sql, &sql_exportcow, f);
	sqlite3_free(sql);
	if (rc != SQLITE_OK)
	{
		printf("There was an error while exporting to coWPAtty hash DB.\n");
	}

	fclose(f);
	printf("Done.\n");
}

// import a cowpatty file
static int import_cowpatty(sqlite3 * db, char * filename)
{
	struct hashdb_rec * rec = NULL;
	struct cowpatty_file * hashdb;
	sqlite3_stmt * stmt;
	char * sql;
	int essid_id;

	hashdb = open_cowpatty_hashdb(filename, "r");
	if (hashdb == NULL)
	{
		printf("Failed opening file\n");
		return (0);
	}
	else if (hashdb->error[0])
	{
		printf("Failed opening file: %s\n", hashdb->error);
		close_free_cowpatty_hashdb(hashdb);
		return (0);
	}

	// We need protection so concurrent transactions can't smash the
	// ID-references
	sql_exec(db, "BEGIN;");

	sql = sqlite3_mprintf("INSERT OR IGNORE INTO essid (essid) VALUES ('%q');",
						  hashdb->ssid);
	sql_exec(db, sql);
	sqlite3_free(sql);

	// since there is only one essid per file, we can determine it's ID now
	sql = sqlite3_mprintf("SELECT essid_id FROM essid WHERE essid = '%q'",
						  hashdb->ssid);
	essid_id = query_int(db, sql);
	sqlite3_free(sql);
	if (essid_id == 0)
	{
		close_free_cowpatty_hashdb(hashdb);
		sql_exec(db, "ROLLBACK;");
		printf("ESSID couldn't be inserted. I've given up.\n");
		return (0);
	}

	sql = sqlite3_mprintf(
		"CREATE TEMPORARY TABLE import (passwd text, pmk blob);", essid_id);
	sql_exec(db, sql);
	sqlite3_free(sql);
	sql_prepare(
		db, "INSERT INTO import (passwd,pmk) VALUES (@pw,@pmk)", &stmt, -1);

	printf("Reading...\n");

	while (!exit_airolib && (rec = read_next_cowpatty_record(hashdb)))
	{
		if (verify_passwd(rec->word) == 0)
		{
			sqlite3_bind_text(
				stmt, 1, rec->word, strlen(rec->word), SQLITE_TRANSIENT);
			sqlite3_bind_blob(
				stmt, 2, &rec->pmk, sizeof(rec->pmk), SQLITE_TRANSIENT);
			if (sql_step(stmt, -1) == SQLITE_DONE)
			{
				sqlite3_reset(stmt);
			}
			else
			{
				printf("Error while inserting record into database.\n");
				sqlite3_finalize(stmt);
				sql_exec(db, "ROLLBACK;");
				close_free_cowpatty_hashdb(hashdb);
				free(rec->word);
				free(rec);
				return (1);
			}
		}
		else
		{
			fprintf(stdout,
					"Invalid password %s will not be imported.\n",
					rec->word);
		}
		free(rec->word);
		free(rec);
	}

	// Finalize
	sqlite3_finalize(stmt);

	// Rollback if any error happened.
	if (hashdb->error[0])
	{
		printf("Error: %s, rolling back\n", hashdb->error);
		sql_exec(db, "ROLLBACK;");
		close_free_cowpatty_hashdb(hashdb);
		return (1);
	}
	close_free_cowpatty_hashdb(hashdb);

	printf("Updating references...\n");
	sql_exec(
		db, "INSERT OR IGNORE INTO passwd (passwd) SELECT passwd FROM import;");

	// TODO Give the user a choice to either INSERT OR UPDATE or INSERT OR
	// IGNORE
	printf("Writing...\n");
	sql = sqlite3_mprintf("INSERT OR IGNORE INTO pmk (essid_id,passwd_id,pmk) "
						  "SELECT %i,passwd.passwd_id,import.pmk FROM import "
						  "INNER JOIN passwd ON passwd.passwd = import.passwd;",
						  essid_id);
	sql_exec(db, sql);
	sqlite3_free(sql);

	sql_exec(db, "COMMIT;");

	return (1);
}

static int import_ascii(sqlite3 * db, const char * mode, const char * filename)
{
	FILE * f = NULL;
	sqlite3_stmt * stmt;
	char buffer[63 + 1];
	int imported = 0;
	int ignored = 0;
	int imode = 0;

	if (strcasecmp(mode, IMPORT_ESSID) == 0)
	{
		imode = 0;
	}
	else if (strcasecmp(mode, IMPORT_PASSWD) == 0)
	{
		imode = 1;
	}
	else
	{
		printf("Specify either 'essid' or 'passwd' as import mode.\n");
		return (0);
	}

	if (strcmp(filename, "-") == 0)
	{
		f = stdin;
	}
	else
	{
		f = fopen(filename, "r");
	}
	if (f == NULL)
	{
		printf("Could not open file/stream for reading.\n");
		return (0);
	}

	char * sql = sqlite3_mprintf(
		"INSERT OR IGNORE INTO %q (%q) VALUES (@v);", mode, mode);
	sql_prepare(db, sql, &stmt, -1);
	sqlite3_free(sql);

	sql_exec(db, "BEGIN;");
	printf("Reading file...\n");
	while (!exit_airolib && fgets(buffer, sizeof(buffer), f) != 0)
	{
		int i = strlen(buffer);
		if (i > 0 && buffer[i - 1] == '\n') buffer[--i] = '\0';
		if (i > 0 && buffer[i - 1] == '\r') buffer[--i] = '\0';
		imported++;
		if ((imode == 0 && verify_essid(buffer) == 0)
			|| (imode == 1 && verify_passwd(buffer) == 0))
		{
			sqlite3_bind_text(
				stmt, 1, buffer, strlen(buffer), SQLITE_TRANSIENT);
			if (sql_step(stmt, -1) == SQLITE_DONE)
			{
				sqlite3_reset(stmt);
			}
			else
			{
				printf("Error while inserting record into database.\n");
				sql_exec(db, "ROLLBACK;");
				sqlite3_finalize(stmt);
				fclose(f);
				return (1);
			}
		}
		else
		{
			ignored++;
		}
		if (imported % 1000 == 0)
		{
			fprintf(stdout,
					"%i lines read, %i invalid lines ignored.\r",
					imported,
					ignored);
			fflush(stdout);
		}
	}
	sqlite3_finalize(stmt);

	if (!feof(f) && !exit_airolib)
	{
		printf("Error while reading file.\n");
		sql_exec(db, "ROLLBACK;");
		fclose(f);
		return (1);
	}
	fclose(f);

	printf("Writing...\n");
	sql_exec(db, "COMMIT;");

	printf("Done.\n");
	return (1);
}

// sql function. takes ESSID and PASSWD, gives PMK
static void
sql_calcpmk(sqlite3_context * context, int argc, sqlite3_value ** values)
{
	REQUIRE(context != NULL);
	REQUIRE(values != NULL);

	unsigned char pmk[40];
	char * passwd = (char *) sqlite3_value_blob(values[1]);
	char * essid = (char *) sqlite3_value_blob(values[0]);
	if (argc < 2 || passwd == 0 || essid == 0)
	{
		sqlite3_result_error(
			context, "SQL function PMK() called with invalid arguments.\n", -1);
		return;
	}
	calc_pmk(passwd, essid, pmk);
	sqlite3_result_blob(context, pmk, 32, SQLITE_TRANSIENT);
}

#ifdef HAVE_REGEXP
static void
sqlite_regexp(sqlite3_context * context, int argc, sqlite3_value ** values)
{
	REQUIRE(context != NULL);
	REQUIRE(values != NULL);

	int ret;
	regex_t regex;
	char * reg = (char *) sqlite3_value_text(values[0]);
	char * text = (char *) sqlite3_value_text(values[1]);

	if (argc != 2 || reg == 0 || text == 0)
	{
		sqlite3_result_error(
			context,
			"SQL function regexp() called with invalid arguments.\n",
			-1);
		return;
	}

	ret = regcomp(&regex, reg, REG_EXTENDED | REG_NOSUB);
	if (ret != 0)
	{
		sqlite3_result_error(context, "error compiling regular expression", -1);
		return;
	}

	ret = regexec(&regex, text, 0, NULL, 0);
	regfree(&regex);

	sqlite3_result_int(context, (ret != REG_NOMATCH));
}
#endif

static int initDataBase(const char * filename, sqlite3 ** db)
{
	REQUIRE(filename != NULL);
	REQUIRE(db != NULL);

	int rc = sqlite3_open(filename, &(*db));
	if (rc != SQLITE_OK)
	{
		sql_error(*db);
		sqlite3_close(*db);

		// May be useful later
		return (rc);
	}

	sql_exec(*db,
			 "create table essid (essid_id integer primary key "
			 "autoincrement, essid text, prio integer default 64);");
	sql_exec(*db,
			 "create table passwd (passwd_id integer primary key "
			 "autoincrement, passwd text);");
	sql_exec(*db,
			 "create table pmk (pmk_id integer primary key autoincrement, "
			 "passwd_id int, essid_id int, pmk blob);");
	sql_exec(*db,
			 "create table workbench (wb_id integer primary key "
			 "autoincrement, essid_id integer, passwd_id integer, lockid "
			 "integer default 0);");
	sql_exec(*db, "create index lock_lockid on workbench (lockid);");
	sql_exec(*db, "create index pmk_pw on pmk (passwd_id);");
	sql_exec(*db, "create unique index essid_u on essid (essid);");
	sql_exec(*db, "create unique index passwd_u on passwd (passwd);");
	sql_exec(*db, "create unique index ep_u on pmk (essid_id,passwd_id);");
	sql_exec(*db,
			 "create unique index wb_u on workbench (essid_id,passwd_id);");
	sql_exec(*db,
			 "CREATE TRIGGER delete_essid DELETE ON essid BEGIN DELETE "
			 "FROM pmk WHERE pmk.essid_id = OLD.essid_id; DELETE FROM "
			 "workbench WHERE workbench.essid_id = OLD.essid_id; END;");
	sql_exec(*db,
			 "CREATE TRIGGER delete_passwd DELETE ON passwd BEGIN DELETE "
			 "FROM pmk WHERE pmk.passwd_id = OLD.passwd_id; DELETE FROM "
			 "workbench WHERE workbench.passwd_id = OLD.passwd_id; END;");

#ifdef SQL_DEBUG
	sql_exec(*db, "begin;");
	sql_exec(*db, "insert into essid (essid,prio) values ('e',random())");
	sql_exec(*db, "insert into passwd (passwd) values ('p')");
	sql_exec(*db,
			 "insert into essid (essid,prio) select essid||'a',random() "
			 "from essid;");
	sql_exec(*db,
			 "insert into essid (essid,prio) select essid||'b',random() "
			 "from essid;");
	sql_exec(*db,
			 "insert into essid (essid,prio) select essid||'c',random() "
			 "from essid;");
	sql_exec(*db,
			 "insert into essid (essid,prio) select essid||'d',random() "
			 "from essid;");
	sql_exec(*db,
			 "insert into passwd (passwd) select passwd||'a' from passwd;");
	sql_exec(*db,
			 "insert into passwd (passwd) select passwd||'b' from passwd;");
	sql_exec(*db,
			 "insert into passwd (passwd) select passwd||'c' from passwd;");
	sql_exec(*db,
			 "insert into passwd (passwd) select passwd||'d' from passwd;");
	sql_exec(*db,
			 "insert into passwd (passwd) select passwd||'e' from passwd;");
	sql_exec(*db,
			 "insert into pmk (essid_id,passwd_id) select "
			 "essid_id,passwd_id from essid,passwd limit 1000000;");
	sql_exec(*db, "commit;");
#endif

	sqlite3_close(*db);
	printf("Database <%s> successfully created\n", filename);
	return (0);
}

static int
check_for_db(sqlite3 ** db, const char * filename, int can_create, int readonly)
{
	REQUIRE(filename != NULL);

	struct stat dbfile;
	int rc;
	int accessflags = R_OK | W_OK;
	if (readonly) accessflags = R_OK;

	// Check if DB exist. If it does not, initialize it
	if (access(filename, accessflags))
	{
		printf("Database <%s> does not already exist, ", filename);
		if (can_create)
		{
			printf("creating it...\n");

			rc = initDataBase(filename, db);

			if (rc)
			{
				printf("Error initializing database (return code: %d), "
					   "exiting...\n",
					   rc);
				return (1);
			}
		}
		else
		{
			printf("exiting ...\n");
			return (1);
		}
	}
	else
	{
		if (stat(filename, &dbfile))
		{
			perror("stat()");
			return (1);
		}
		if ((S_ISREG(dbfile.st_mode) && !S_ISDIR(dbfile.st_mode)) == 0)
		{
			printf("\"%s\" does not appear to be a file.\n", filename);
			return (1);
		}
	}

	rc = sqlite3_open(filename, &(*db));
	if (rc)
	{
		sql_error(*db);
		sqlite3_close(*db);
		return (1);
	}

	// TODO: Sanity check: Table definitions, index

	// register new functions to be used in SQL statements
	if (sqlite3_create_function(
			*db, "PMK", 2, SQLITE_ANY, 0, &sql_calcpmk, 0, 0)
		!= SQLITE_OK)
	{
		printf("Failed creating PMK function.\n");
		sql_error(*db);
		sqlite3_close(*db);
		return (1);
	}
	if (sqlite3_create_function(
			*db, "VERIFY_ESSID", 1, SQLITE_ANY, 0, &sql_verify_essid, 0, 0)
		!= SQLITE_OK)
	{
		printf("Failed creating VERIFY_ESSID function.\n");
		sql_error(*db);
		sqlite3_close(*db);
		return (1);
	}
	if (sqlite3_create_function(
			*db, "VERIFY_PASSWD", 1, SQLITE_ANY, 0, &sql_verify_passwd, 0, 0)
		!= SQLITE_OK)
	{
		printf("Failed creating VERIFY_PASSWD function.\n");
		sql_error(*db);
		sqlite3_close(*db);
		return (1);
	}
#ifdef HAVE_REGEXP
	if (sqlite3_create_function(
			*db, "regexp", 2, SQLITE_ANY, 0, &sqlite_regexp, 0, 0)
		!= SQLITE_OK)
	{
		printf("Failed creating regexp() handler.\n");
		sql_error(*db);
		sqlite3_close(*db);
		return (1);
	}
#endif

	return (0);
}

int main(int argc, char ** argv)
{
	sqlite3 * db;
	int option_index, option;
	exit_airolib = 0;

	if (argc < 3)
	{
		print_help(NULL);
		return (EXIT_FAILURE);
	}

	db = NULL;

	option_index = 0;

	static const struct option long_options[]
		= {{"batch", 0, 0, 'b'},
		   {"clean", 2, 0, 'c'},
		   {"export", 2, 0, 'e'},
		   {"h", 0, 0, 'h'},
		   {"help", 0, 0, 'h'},
		   {"import", 2, 0, 'i'},
		   {"sql", 1, 0, 's'},
		   {"stats", 2, 0, 't'},
		   {"statistics", 2, 0, 't'},
		   {"verify", 2, 0, 'v'},
		   {"vacuum", 2, 0, 'c'},
		   // TODO: implement options like '-e essid' to limit
		   //       operations to a certain essid where possible
		   {"essid", 1, 0, 'd'},
		   {0, 0, 0, 0}};

	ac_crypto_init();

	signal(SIGINT, sighandler);
	signal(SIGQUIT, sighandler);
	signal(SIGTERM, sighandler);

	option = getopt_long(
		argc, argv, "bc:d:e:hi:s:t:v:", long_options, &option_index);

	if (option > 0)
	{
		switch (option)
		{
			case 'b':
				// Batch
				if (check_for_db(&db, argv[1], 0, 1))
				{
					return (EXIT_FAILURE);
				}
				batch_process(db);

				break;

			case 'c':
				// Clean
				if (check_for_db(&db, argv[1], 0, 0))
				{
					return (EXIT_FAILURE);
				}
				vacuum(db,
					   (argc > 3 && strcasecmp(argv[3], "all") == 0) ? 1 : 0);

				break;

			case 'e':

				if (argc < 4)
				{
					print_help("You must specify an export format.");
				}
				else if (strcmp(argv[3], EXPORT_COWPATTY) == 0)
				{
					if (argc < 6)
					{
						print_help("You must specify essid and output file.");
					}
					else
					{
						// Export
						if (check_for_db(&db, argv[1], 0, 0))
						{
							return (EXIT_FAILURE);
						}
						export_cowpatty(db, argv[4], argv[5]);
					}
				}
				else
				{
					print_help("Invalid export format specified.");
				}

				break;

			case ':':
			case '?':
			case 'h':
				// Show help
				print_help(NULL);

				break;

			case 'i':
				// Import

				if (argc < 5)
				{
					print_help("You must specify an import format and a file.");
				}
				else if (strcasecmp(argv[3], IMPORT_COWPATTY) == 0)
				{
					if (check_for_db(&db, argv[1], 1, 0))
					{
						return (EXIT_FAILURE);
					}
					import_cowpatty(db, argv[4]);
				}
				else if (strcasecmp(argv[3], IMPORT_ESSID) == 0)
				{
					if (check_for_db(&db, argv[1], 1, 0))
					{
						return (EXIT_FAILURE);
					}
					import_ascii(db, IMPORT_ESSID, argv[4]);
				}
				else if (strcasecmp(argv[3], IMPORT_PASSWD) == 0
						 || strcasecmp(argv[3], IMPORT_PASSWD_ALT) == 0)
				{
					if (check_for_db(&db, argv[1], 1, 0))
					{
						return (EXIT_FAILURE);
					}
					import_ascii(db, IMPORT_PASSWD, argv[4]);
				}
				else
				{
					print_help("Invalid import format specified.");
					return (EXIT_FAILURE);
				}
				break;
			case 's':
				// SQL

				// We don't know if the SQL order is changing the file or not
				if (check_for_db(&db, argv[1], 0, 0))
				{
					return (EXIT_FAILURE);
				}

				sql_stdout(db, argv[3], 0);

				break;

			case 't':
				// Stats
				if (check_for_db(&db, argv[1], 0, 1))
				{
					return (EXIT_FAILURE);
				}

				show_stats(db, (argv[3] == NULL) ? 0 : 1);

				break;

			case 'v':
				// Verify
				if (check_for_db(
						&db,
						argv[1],
						0,
						(argc > 3 && strcasecmp(argv[3], "all") == 0) ? 0 : 1))
				{
					return (EXIT_FAILURE);
				}

				verify(db,
					   (argc > 3 && strcasecmp(argv[3], "all") == 0) ? 1 : 0);
				break;

			default:
				print_help("Invalid option");
				break;
		}
	}
	else
	{
		print_help(NULL);
	}

	if (db) sqlite3_close(db);

	return (EXIT_SUCCESS);
}
