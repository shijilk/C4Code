DECLARE @max_rows as INTEGER = 0;
DECLARE @max_rows_per_job as INTEGER = 0;
 
EXECUTE master.dbo.xp_instance_regread 
    N'HKEY_LOCAL_MACHINE',
    N'SOFTWARE\Microsoft\MSSQLServer\SQLServerAgent',
    N'JobHistoryMaxRows',
    @max_rows OUTPUT,
    N'no_output';
 
EXECUTE master.dbo.xp_instance_regread 
    N'HKEY_LOCAL_MACHINE',
    N'SOFTWARE\Microsoft\MSSQLServer\SQLServerAgent',
    N'JobHistoryMaxRowsPerJob',
    @max_rows_per_job OUTPUT,
    N'no_output';
 
select @max_rows as MaxRows, @max_rows_per_job as MaxPerJob;


-- most log size is set to default values of 1000 and 100

-- we would prefer them to be 99999 and 1000

-- The Query to change the values is :

/*
EXEC msdb.dbo.sp_set_sqlagent_properties 
    @jobhistory_max_rows = 99999,
    @jobhistory_max_rows_per_job = 1000
*/