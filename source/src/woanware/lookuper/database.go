package main

const SQL_CREATE_TABLE_JOB string =
	`CREATE TABLE "job" (
		'type'					smallint NOT NULL,
		'api_keys'				text,
		'are_api_keys_private'	smallint
	);`

const SQL_CREATE_TABLE_WORK string =
`CREATE TABLE "work" (
	'md5'	text NOT NULL,
	'response_code'	smallint,
	'data'	text
);`

const SQL_CREATE_TABLE_VT_HASH string =
`CREATE TABLE 'vt_hash' (
	'id'	INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	'md5'	text NOT NULL,
	'sha256'	text NOT NULL,
	'positives'	smallint NOT NULL,
	'total'	smallint NOT NULL,
	'permalink'	text,
	'scans'	text,
	'scan_date'	bigint NOT NULL,
	'update_date'	bigint NOT NULL
);`

const SQL_CREATE_TABLE_VT_DOMAIN_DETECTED_URL string =
`CREATE TABLE "vt_domain_detected_url" (
	'id'	INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	'url'	text NOT NULL,
	'url_md5'	text NOT NULL,
	'positives'	smallint NOT NULL,
	'total'	smallint NOT NULL,
	'scan_date'	bigint NOT NULL,
	'update_date'	bigint NOT NULL,
	'domain_md5'	text
);`

const SQL_CREATE_TABLE_VT_DOMAIN_RESOLUTION string =
`CREATE TABLE "vt_domain_resolution" (
	'id'	INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	'domain_md5'	text NOT NULL,
	'last_resolved'	bigint NOT NULL,
	'ip_address'	bigint NOT NULL,
	'update_date'	bigint
);`

const SQL_CREATE_TABLE_TE_HASH string =
`CREATE TABLE "te_hash" (
	'id'	INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	'md5'	text NOT NULL,
	'name'	text,
	'severities'	text,
	'scan_date'	bigint NOT NULL,
	'update_date'	bigint NOT NULL
);`

const SQL_CREATE_TABLE_VT_IP_DETECTED_URL string =
`CREATE TABLE "vt_ip_detected_url" (
	'id'	INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	'ip'	bigint NOT NULL,
	'url'	text NOT NULL,
	'url_md5'	text NOT NULL,
	'positives'	smallint NOT NULL,
	'total'	smallint NOT NULL,
	'scan_date'	bigint NOT NULL,
	'update_date'	bigint NOT NULL
);`

const SQL_CREATE_TABLE_VT_IP_RESOLUTION string =
`CREATE TABLE "vt_ip_resolution" (
	'id'	INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	'ip'	bigint NOT NULL,
	'last_resolved'	bigint NOT NULL,
	'host_name'	text NOT NULL,
	'host_name_md5'	text NOT NULL,
	'update_date'	bigint NOT NULL
);`

const SQL_CREATE_TABLE_TE_STRING string =
`CREATE TABLE "te_string" (
	'id'	INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	'string'	text NOT NULL,
	'count'	integer,
	'update_date'	bigint NOT NULL
);`

const SQL_CREATE_TABLE_VT_URL string =
`CREATE TABLE "vt_url" (
	'id'	INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	'url'	text NOT NULL,
	'url_md5'	text NOT NULL,
	'positives'	smallint NOT NULL,
	'total'	smallint NOT NULL,
	'permalink'	text,
	'scans'	text,
	'scan_date'	bigint NOT NULL,
	'update_date'	bigint NOT NULL
);`

const SQL_CREATE_TABLE_GOOGLE_SAFE_BROWSING string =
`CREATE TABLE "google_safe_browsing" (
	'id'	INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	'url'	text,
	'url_md5'	text,
	'data'	text,
	'update_date'	bigint
);`

const SQL_CREATE_INDEX_WORK string =
`CREATE INDEX 'idx_work' ON 'work' ('md5');`

const SQL_CREATE_INDEX_VT_HASH_MD5 string =
	`CREATE INDEX 'idx_vt_hash_md5' ON 'vt_hash' ('md5');`

const SQL_CREATE_INDEX_VT_HASH_SHA256 string =
	`CREATE INDEX 'idx_vt_hash_sha256' ON 'vt_hash' ('sha256');`

const SQL_CREATE_INDEX_VT_IP_RESOLUTION string =
	`CREATE INDEX 'idx_vt_ip_resolution' ON 'vt_ip_resolution' ('ip');`

const SQL_CREATE_INDEX_VT_DOMAIN_RESOLUTION string =
	`CREATE INDEX 'idx_vt_domain_resolution' ON 'vt_domain_resolution' ('domain_md5');`

const SQL_CREATE_INDEX_VT_URL string =
	`CREATE INDEX 'idx_vt_url' ON 'vt_url' ('url_md5');`

const SQL_CREATE_INDEX_TE_HASH string =
	`CREATE INDEX 'idx_te_hash' ON 'te_hash' ('md5');`

const SQL_CREATE_INDEX_TE_STRING string =
	`CREATE INDEX 'idx_te_string' ON 'te_string' ('string');`

const SQL_CREATE_INDEX_GSB string =
	`CREATE INDEX 'idx_gsb' ON 'google_safe_browsing' ('url_md5');`

var DATABASE_SQL_CREATES = []string {
	SQL_CREATE_TABLE_JOB,
	SQL_CREATE_TABLE_WORK,
	SQL_CREATE_TABLE_VT_HASH,
	SQL_CREATE_TABLE_VT_DOMAIN_DETECTED_URL,
	SQL_CREATE_TABLE_VT_DOMAIN_RESOLUTION,
	SQL_CREATE_TABLE_TE_HASH,
	SQL_CREATE_TABLE_VT_IP_DETECTED_URL,
	SQL_CREATE_TABLE_VT_IP_RESOLUTION,
	SQL_CREATE_TABLE_TE_STRING,
	SQL_CREATE_TABLE_VT_URL,
	SQL_CREATE_TABLE_GOOGLE_SAFE_BROWSING,
}

var DATABASE_SQL_INDEXES = []string {
	SQL_CREATE_INDEX_WORK,
	SQL_CREATE_INDEX_VT_HASH_MD5,
	SQL_CREATE_INDEX_VT_HASH_SHA256,
	SQL_CREATE_INDEX_VT_IP_RESOLUTION,
	SQL_CREATE_INDEX_VT_DOMAIN_RESOLUTION,
	SQL_CREATE_INDEX_VT_URL,
	SQL_CREATE_INDEX_TE_HASH,
	SQL_CREATE_INDEX_TE_STRING,
	SQL_CREATE_INDEX_GSB,
}