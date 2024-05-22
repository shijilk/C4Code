
-- Look at Suspect Pages table 

SELECT DB_NAME(sp.database_id) AS [Database Name], 
       sp.[file_id], sp.page_id, sp.event_type, 
	   sp.error_count, sp.last_update_date,
	   mf.name AS [Logical Name], mf.physical_name AS [File Path]
FROM msdb.dbo.suspect_pages AS sp WITH (NOLOCK)
INNER JOIN sys.master_files AS mf WITH (NOLOCK)
ON mf.database_id = sp.database_id 
AND mf.file_id = sp.file_id
ORDER BY sp.database_id OPTION (RECOMPILE);

------

-- event_type value descriptions
-- 1 = 823 error caused by an operating system CRC error
--     or 824 error other than a bad checksum or a torn page (for example, a bad page ID)
-- 2 = Bad checksum
-- 3 = Torn page
-- 4 = Restored (The page was restored after it was marked bad)
-- 5 = Repaired (DBCC repaired the page)
-- 7 = Deallocated by DBCC

-- Ideally, this query returns no results. The table is limited to 1000 rows.
-- If you do get results here, you should do further investigation to determine the root cause

-- Manage the suspect_pages Table
-- https://bit.ly/2Fvr1c9
