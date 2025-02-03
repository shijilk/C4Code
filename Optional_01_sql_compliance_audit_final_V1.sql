use master
GO
set nocount on
exec master..sp_configure 'show advanced options',1
reconfigure with override
GO
 IF OBJECT_ID('tempdb..#xconfigurations') IS NOT NULL 
 DROP TABLE #xconfigurations;

create table #xconfigurations 
(name varchar(100),
minimum varchar(100),
maximum varchar(100),
config_value varchar(100),
run_value varchar(100))

insert into #xconfigurations exec master..sp_configure
declare @config_value varchar(50)
select @config_value=config_value from #xconfigurations where name ='xp_cmdshell'

if @config_value = 0
exec master..sp_configure 'xp_cmdshell',1
reconfigure with override
GO

set nocount on 
 IF OBJECT_ID('tempdb..#BlitzResults') IS NOT NULL 
        DROP TABLE #BlitzResults;
    CREATE TABLE #BlitzResults
        (
          ID INT IDENTITY(1, 1) ,
          Servername varchar(300) default @@servername,
          Hardening_component varchar(100),
          Details NVARCHAR(max),
          Findings varchar(max),
          Compliance varchar(20)
         );   

/******* SQL ERRORLOG FILES**********/
 IF OBJECT_ID('tempdb..#SQLREGVALUES') IS NOT NULL 
        DROP TABLE #SQLREGVALUES;
IF OBJECT_ID('tempdb..#Instance') IS NOT NULL 
        DROP TABLE #Instance;
CREATE TABLE #SQLREGVALUES (value VARCHAR(50),data VARCHAR(100))

CREATE TABLE #Instance (value VARCHAR(50),data VARCHAR(50))


DECLARE @Instance VARCHAR(50)
DECLARE @InstanceLoc VARCHAR(50)
DECLARE @RegKey VARCHAR(255)
DECLARE @CPUCount INT
DECLARE @CPUID INT
DECLARE @AffinityMask INT
DECLARE @CPUList VARCHAR(50)
DECLARE @InstCPUCount INT
DECLARE @sql VARCHAR(255)
DECLARE @Database VARCHAR(50)


--get instance location FROM registry
SET @RegKey = 'SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL'

INSERT INTO #Instance EXEC xp_regread 'HKEY_LOCAL_MACHINE', @RegKey, @@servicename

SELECT @InstanceLoc=data FROM #Instance WHERE VALUE = @@servicename

--get audit data FROM registry and insert into #SQLREGVALUES


SET @RegKey = 'SOFTWARE\Microsoft\Microsoft SQL Server\' + @InstanceLoc + '\Setup'

INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE', @RegKey, 'Edition'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE', @RegKey, 'SqlCluster'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE', @RegKey, 'SqlProgramDir'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE', @RegKey, 'SQLDataRoot'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE', @RegKey, 'SQLPath'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE', @RegKey, 'SQLBinRoot'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE', @RegKey, 'Version'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE', @RegKey, 'SP'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE', @RegKey, 'collation'


SET @RegKey = 'SOFTWARE\Microsoft\Microsoft SQL Server\' + @InstanceLoc + '\MSSQLServer\Parameters'

INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE', @RegKey, 'SQLArg0'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE', @RegKey, 'SQLArg1'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE', @RegKey, 'SQLArg2'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE', @RegKey, 'SQLArg3'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE', @RegKey, 'SQLArg4'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE', @RegKey, 'SQLArg5'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE', @RegKey, 'SQLArg6'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE', @RegKey, 'SQLArg7'

SET @RegKey = 'SOFTWARE\Microsoft\Microsoft SQL Server\' + @InstanceLoc + '\MSSQLSERVER'

INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE', @RegKey, 'AuditLevel'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE', @RegKey, 'LoginMode'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE', @RegKey, 'DefaultData'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE', @RegKey, 'DefaultLog'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE', @RegKey, 'BackupDirectory'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE', @RegKey, 'NumErrorLogs'

SET @RegKey = 'SOFTWARE\Microsoft\Microsoft SQL Server\' + @InstanceLoc + '\SQLServerAgent'

INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE', @RegKey, 'RestartSQLServer'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE', @RegKey, 'RestartServer'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE', @RegKey, 'UseDatabaseMail'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE', @RegKey, 'DatabaseMailProfile'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE', @RegKey, 'JobHistoryMaxRows'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE', @RegKey, 'JobHistoryMaxRowsPerJob'


SET @RegKey = 'SOFTWARE\Microsoft\Microsoft SQL Server\' + @InstanceLoc + '\MSSQLSERVER\SuperSocketNetLib\Tcp\IPAll'
--for version 8.8 higher
--HKEY_LOCAL_MACHINE\SOFTWARE\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE', @RegKey, 'TcpDynamicPorts'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE', @RegKey, 'TcpPort'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Wow6432Node\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 

'ExcludedItem_0'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Wow6432Node\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 

'ExcludedItem_1'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Wow6432Node\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 

'ExcludedItem_2'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Wow6432Node\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 

'ExcludedItem_3'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Wow6432Node\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 

'ExcludedItem_4'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Wow6432Node\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 

'ExcludedItem_5'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Wow6432Node\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 

'ExcludedItem_6'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Wow6432Node\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 

'ExcludedItem_7'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Wow6432Node\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 

'ExcludedItem_8'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Wow6432Node\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 

'ExcludedItem_9'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Wow6432Node\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 

'ExcludedItem_10'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Wow6432Node\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 

'ExcludedItem_11'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Wow6432Node\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 

'ExcludedItem_12'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Wow6432Node\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 

'ExcludedItem_13'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Wow6432Node\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 

'ExcludedItem_14'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Wow6432Node\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 

'ExcludedItem_15'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Wow6432Node\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 

'ExcludedItem_16'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Wow6432Node\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 

'ExcludedItem_17'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Wow6432Node\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 

'ExcludedItem_18'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Wow6432Node\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 

'ExcludedItem_19'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Wow6432Node\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 

'ExcludedItem_20'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Wow6432Node\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 

'ExcludedItem_21'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Wow6432Node\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 

'ExcludedItem_22'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Wow6432Node\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 

'ExcludedItem_23'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Wow6432Node\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 

'ExcludedItem_23'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Wow6432Node\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 

'ExcludedItem_25'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Wow6432Node\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 

'ExcludedItem_26'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Wow6432Node\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 

'ExcludedItem_27'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Wow6432Node\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 

'ExcludedItem_28'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Wow6432Node\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 

'ExcludedItem_29'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Wow6432Node\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 

'ExcludedItem_30'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Wow6432Node\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 

'ExcludedItem_31'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Wow6432Node\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 

'ExcludedItem_32'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Wow6432Node\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 

'ExcludedItem_33'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Wow6432Node\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 

'ExcludedItem_34'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Wow6432Node\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 

'ExcludedItem_35'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Wow6432Node\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 

'ExcludedItem_36'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Wow6432Node\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 

'ExcludedItem_37'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Wow6432Node\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 

'ExcludedItem_38'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Wow6432Node\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 

'ExcludedItem_39'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Wow6432Node\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 

'ExcludedItem_40'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Wow6432Node\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 

'ExcludedItem_41'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Wow6432Node\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 

'ExcludedItem_42'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Wow6432Node\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 

'ExcludedItem_43'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Wow6432Node\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 

'ExcludedItem_44'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Wow6432Node\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 

'ExcludedItem_45'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Wow6432Node\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 

'ExcludedItem_46'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Wow6432Node\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 

'ExcludedItem_47'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Wow6432Node\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 

'ExcludedItem_48'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Wow6432Node\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 

'ExcludedItem_50'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Wow6432Node\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 

'ExcludedItem_51'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Wow6432Node\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 

'ExcludedItem_52'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Wow6432Node\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 

'ExcludedItem_53'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Wow6432Node\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 

'ExcludedItem_54'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Wow6432Node\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 

'ExcludedItem_55'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Wow6432Node\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 

'ExcludedItem_56'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Wow6432Node\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 

'ExcludedItem_57'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Wow6432Node\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 

'ExcludedItem_58'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Wow6432Node\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 

'ExcludedItem_59'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Wow6432Node\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 

'ExcludedItem_60'

INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_0'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_1'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_2'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_3'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_4'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_5'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_6'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_7'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_8'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_9'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_10'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_11'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_12'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_13'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_14'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_15'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_16'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_17'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_18'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_19'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_20'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_21'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_22'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_23'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_24'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_25'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_26'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_27'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_28'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_29'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_30'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_31'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_32'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_33'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_34'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_35'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_36'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_37'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_38'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_39'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_40'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_41'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_42'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_43'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_44'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_45'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_46'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_47'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_48'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_49'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_50'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_51'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_52'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_53'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_54'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_55'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_56'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_57'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_58'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_59'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\SystemCore\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_60'

INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_0'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_1'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_2'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_3'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_4'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_5'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_6'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_7'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_8'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_9'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_10'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_11'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_12'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_13'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_14'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_15'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_16'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_17'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_18'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_19'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_20'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_21'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_22'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_23'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_24'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_25'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_26'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_27'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_28'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_29'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_30'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_31'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_32'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_33'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_34'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_35'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_36'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_37'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_38'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_39'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_40'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_41'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_42'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_43'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_44'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_45'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_46'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_47'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_48'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_49'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_50'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_51'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_52'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_53'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_54'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_55'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_56'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_57'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_58'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_59'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\McAfee\VSCore\On Access Scanner\McShield\Configuration\Default', 'ExcludedItem_60'

UPDATE #SQLREGVALUES 
SET value = 'Antivirusprofile' where  value like 'ExcludedItem%'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-

4F3A74704073}','IsInstalled'
INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-

4F3A74704073}','IsInstalled'
UPDATE #SQLREGVALUES SET value = 'Internet_download' where  value like 'IsInstalled%'

INSERT INTO #SQLREGVALUES EXEC xp_regread 'HKEY_CURRENT_USER','Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing','State'
UPDATE #SQLREGVALUES SET value = 'Internet_Explorer' where  value like 'state%'
BEGIN 

INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'Internet_Explorer',+ data ,'Internet_Explorer settings are not configured correctly','Non Compliant' from #SQLREGVALUES where value 

='Internet_Explorer' and data <>146944
 declare @sval int 
select @sval=COUNT(*) from #BlitzResults where Hardening_component='Internet_Explorer'
if @sval=0 
INSERT  INTO #BlitzResults
            (   Hardening_component,
             Details,
              findings,
              Compliance
            )
           SELECT 'Internet_Explorer',+ data ,'Internet_Explorer settings are configured correctly','Compliant' from #SQLREGVALUES where value ='Internet_Explorer'
END

BEGIN 

INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'Internet_download',+ data ,'Internet_download are not configured correctly','Non Compliant' from #SQLREGVALUES where value ='Internet_download' and 

data <>0

select @sval=COUNT(*) from #BlitzResults where Hardening_component='Internet_download'
if @sval=0 
INSERT  INTO #BlitzResults
            (   Hardening_component,
             Details,
              findings,
              Compliance
            )
           SELECT 'Internet_download',+ data ,'Internet_download are configured correctly','Compliant' from #SQLREGVALUES where value ='Internet_download'
END

BEGIN 

INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'SQL COLLATION',+ data ,'SQL COLLATION IS NOT SET TO DEFAULT SQL_Latin1_General_CP1_CI_AS ','Non Compliant' from #SQLREGVALUES where value 

='COLLATION'  and data !='SQL_Latin1_General_CP1_CI_AS'

select @sval=COUNT(*) from #BlitzResults where Hardening_component='SQL COLLATION'
if @sval=0 
INSERT  INTO #BlitzResults
            (   Hardening_component,
             Details,
              findings,
              Compliance
            )
           SELECT 'SQL COLLATION',+ data ,'SQL COLLATION SET TO DEFAULT SQL_Latin1_General_CP1_CI_AS','Compliant' from #SQLREGVALUES where value ='COLLATION'
END


   
BEGIN 

INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'Error log files',+ data ,'No of Error log files are not configured correctly','Non Compliant' from #SQLREGVALUES where value ='NumErrorLogs' and 

data <>12

select @sval=COUNT(*) from #BlitzResults where Hardening_component='Error log files'
if @sval=0 
INSERT  INTO #BlitzResults
            (   Hardening_component,
             Details,
              findings,
              Compliance
            )
           SELECT 'Error log files',+ data ,'No of Error log files are configured correctly','Compliant' from #SQLREGVALUES where value ='NumErrorLogs'
END

BEGIN 

INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'SQLAGENT JobHistoryMaxRows',+ data ,'JobHistoryMaxRows are not configured correctly','Non Compliant' from #SQLREGVALUES where value 

='JobHistoryMaxRows' and data <>10000

select @sval=COUNT(*) from #BlitzResults where Hardening_component='SQLAGENT JobHistoryMaxRows'
if @sval=0 
INSERT  INTO #BlitzResults
            (   Hardening_component,
             Details,
              findings,
              Compliance
            )
           SELECT 'SQLAGENT JobHistoryMaxRows',+ data ,'SQLAGENT JobHistoryMaxRows are configured correctly','Compliant' from #SQLREGVALUES where value 

='JobHistoryMaxRows'
END

BEGIN 

INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'SQLAGENT JobHistoryMaxRowsPerJob',+ data ,'SQLAGENT JobHistoryMaxRowsPerJob are not configured correctly','Non Compliant' from #SQLREGVALUES where 

value ='JobHistoryMaxRowsPerJob' and data <>1000
select @sval=COUNT(*) from #BlitzResults where Hardening_component='SQLAGENT JobHistoryMaxRowsPerJob'
if @sval=0 
INSERT  INTO #BlitzResults
            (   Hardening_component,
             Details,
              findings,
              Compliance
            )
           SELECT 'SQLAGENT JobHistoryMaxRowsPerJob', data ,'SQLAGENT JobHistoryMaxRowsPerJob are configured correctly','Compliant' from #SQLREGVALUES where value 

='JobHistoryMaxRowsPerJob'
END

BEGIN 

INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'SQL Trace flags', data ,'SQL Trace flags -T1118 are configured correctly','Compliant' from #SQLREGVALUES where value ='SQLArg3' and data ='-T1118'
select @sval=COUNT(*) from #BlitzResults where Hardening_component='SQL Trace flags' and  Details='-T1118'
if @sval=0

INSERT  INTO #BlitzResults
            (   Hardening_component,
             Details,
              findings,
              Compliance
            )
           SELECT 'SQL Trace flags','-T1118' ,'SQL Trace flags -T1118 are not configured correctly','Non Compliant' --from #SQLREGVALUES where value ='SQLArg3'
END

BEGIN 

INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'SQL Trace flags', data ,'SQL Trace flags -T3023 are configured correctly','Compliant' from #SQLREGVALUES where value ='SQLArg4' and data ='-T3023'
select @sval=COUNT(*) from #BlitzResults where Hardening_component='SQL Trace flags'and Details='-T3023'
if @sval=0
INSERT  INTO #BlitzResults
            (   Hardening_component,
             Details,
              findings,
              Compliance
            )
           SELECT 'SQL Trace flags','-T3023' ,'SQL Trace flags -T3023 are not configured correctly','Non Compliant' --from #SQLREGVALUES where value ='SQLArg3'
END

BEGIN 

INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'SQL Trace flags', data ,'SQL Trace flags -T1204 are configured correctly','Compliant' from #SQLREGVALUES where value ='SQLArg5' and data ='-T1204'
select @sval=COUNT(*) from #BlitzResults where Hardening_component='SQL Trace flags'and Details='-T1204'
if @sval=0
INSERT  INTO #BlitzResults
            (   Hardening_component,
             Details,
              findings,
              Compliance
            )
           SELECT 'SQL Trace flags','-T1204' ,'SQL Trace flags -T1204 are not configured correctly','Non Compliant' --from #SQLREGVALUES where value ='SQLArg3'
END

BEGIN 

INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'SQL Trace flags', data ,'SQL Trace flags -T1222 are configured correctly','Compliant' from #SQLREGVALUES where value ='SQLArg6' and data ='-T1222'
select @sval=COUNT(*) from #BlitzResults where Hardening_component='SQL Trace flags' and Details='-T1222'
if @sval=0
INSERT  INTO #BlitzResults
            (   Hardening_component,
             Details,
              findings,
              Compliance
            )
           SELECT 'SQL Trace flags','-T1222' ,'SQL Trace flags -T1222 are not configured correctly','Non Compliant' 
END


declare @sqlversion varchar(200)
declare @productlevel varchar(200)
select @sqlversion=SUBSTRING(@@VERSION, 1, (PATINDEX('%(%', @@VERSION))-1) 
select @productlevel=convert(varchar,serverproperty('productlevel'))

if @sqlversion='Microsoft SQL Server 2008 R2'and @productlevel='SP3'
BEGIN
INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'SQL ServicePack', @sqlversion+' service pack:'+data  ,'SQL Server is running with desired Service pack','Compliant' from #SQLREGVALUES where value 

='sp'
END
else if @sqlversion='Microsoft SQL Server 2008'and @productlevel='SP3'
BEGIN
INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'SQL ServicePack', @sqlversion+' service pack:'+data  ,'SQL Server is running with desired Service pack','Compliant' from #SQLREGVALUES where value 

='sp'
END
else if @sqlversion='Microsoft SQL Server 2012'and @productlevel='SP3'
BEGIN
INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'SQL ServicePack', @sqlversion+' service pack:'+data  ,'SQL Server is running with desired Service pack','Compliant' from #SQLREGVALUES where value 

='sp'
END
else if @sqlversion='Microsoft SQL Server 2014'and @productlevel='SP1'
BEGIN
INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'SQL ServicePack', @sqlversion+' service pack:'+data  ,'SQL Server is running with desired Service pack','Compliant' from #SQLREGVALUES where value 

='sp'
END

ELSE
BEGIN
INSERT  INTO #BlitzResults
            (   Hardening_component,
             Details,
              findings,
              Compliance
            )
           SELECT 'SQL ServicePack',@sqlversion+' service pack:'+ data  ,'SQL Server is not updated with latest Service pack','Non Compliant' from #SQLREGVALUES where 

value ='sp'
END


BEGIN 

INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'SQL PORT NUMBER', 'SQL PORT: ' + data ,'SQL PORT NUMBER is set to 21443 as per hardening standards','Compliant' from #SQLREGVALUES where value 

='TcpPort' and data ='21443'
select @sval=COUNT(*) from #BlitzResults where Hardening_component='SQL PORT NUMBER'
if @sval=0
INSERT  INTO #BlitzResults
            (   Hardening_component,
             Details,
              findings,
              Compliance
            )
           SELECT 'SQL PORT NUMBER','SQL PORT: ' + data ,'SQL PORT NUMBER is not set as per hardening standards','Non Compliant' from #SQLREGVALUES where value 

='TcpPort'
END

BEGIN 

INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'SQL DYNAMIC PORT NUMBER', 'SQL PORT: ' + data ,'SQL DYNAMIC PORT NUMBER is not set as per hardening standards','Compliant' from #SQLREGVALUES where 

value ='TcpDynamicPorts' and data is null
            Select @sval=COUNT(*) from #BlitzResults where Hardening_component='SQL DYNAMIC PORT NUMBER' 
if @sval=0
INSERT  INTO #BlitzResults
            (   Hardening_component,
             Details,
              findings,
              Compliance
            )
           SELECT 'SQL DYNAMIC PORT NUMBER','SQL PORT: ' + data ,'SQL DYNAMIC PORT NUMBER is set which is not recommended','Non Compliant' from #SQLREGVALUES where 

value ='TcpDynamicPorts'
END

/********WINDOWS FIREWALL STATUS**********/
IF OBJECT_ID('tempdb..#firewallstate') IS NOT NULL 
 DROP TABLE #firewallstate;
create table #firewallstate (returnval varchar(500))

exec xp_cmdshell 'netsh advfirewall Show allprofiles state >c:\monitoring\firewallstate.txt',no_output

BULK INSERT #firewallstate 
FROM 'C:\monitoring\firewallstate.txt'
WITH
(
ROWTERMINATOR = '\n',DATAFILETYPE='widechar'
)


delete from #firewallstate where returnval is null or returnval like '%--%' or returnval='Ok.'

BEGIN 

INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'windows firewall',returnval,'windows firewall is on','Non Compliant' from #firewallstate where returnval like '%on%'

select @sval=COUNT(*) from #BlitzResults where Hardening_component='windows firewall'
if @sval=0 
INSERT  INTO #BlitzResults
            (   Hardening_component,
             Details,
              findings,
              Compliance
            )
            SELECT 'windows firewall',returnval,'windows firewall is off as per Hardening standard','Compliant' from #firewallstate 
END

/********POWER SETTINGS **********/
IF OBJECT_ID('tempdb..#powersettings') IS NOT NULL 
        DROP TABLE #powersettings;
create table #powersettings (returnval varchar(500))

exec xp_cmdshell 'powercfg -list >c:\monitoring\powersettings.txt',no_output

BULK INSERT #powersettings 
FROM 'C:\monitoring\powersettings.txt'
WITH
(
ROWTERMINATOR = '\n',DATAFILETYPE='widechar'
)


declare @guidvalue varchar(200)
declare @sqlstr varchar(500)

delete from #powersettings where returnval ='Existing Power Schemes (* Active)' or returnval =  '-----------------------------------'

BEGIN 

INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'Power settings',returnval,'power settings is not configured correctly','Non Compliant' from #powersettings where returnval  like '%(High 

performance)'

select @sval=COUNT(*) from #BlitzResults where Hardening_component='Power settings'
if @sval=0 
INSERT  INTO #BlitzResults
            (   Hardening_component,
             Details,
              findings,
              Compliance
            )
            SELECT 'Power settings',returnval,'power settings is set to High performance mode as per Hardening standard','Compliant' from #powersettings where 

returnval like '%(High performance) *'
END
/********MEMORY SETTINGS**********/
IF OBJECT_ID('tempdb..#configurations') IS NOT NULL 
        DROP TABLE #configurations;
create table #configurations 
(name varchar(100),
minimum varchar(100),
maximum varchar(100),
config_value varchar(100),
run_value varchar(100))

insert into #configurations exec master..sp_configure


BEGIN 

INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            
            SELECT 'Max Memory Settings','Memory :'+ config_value + ' MB','Max Memory Settings is not configured correctly','Non Compliant' from #configurations where 

name ='max server memory (MB)' and config_value='2147483647'

select @sval=COUNT(*) from #BlitzResults where Hardening_component='Max Memory Settings'
if @sval=0 
INSERT  INTO #BlitzResults
            (   Hardening_component,
             Details,
              findings,
              Compliance
            )
           SELECT 'Max Memory Settings','Memory :'+ config_value + ' MB','Max Memory Settings is configured correctly','Compliant' from #configurations  where name 

='max server memory (MB)' 
END

/********Backup compression SETTINGS**********/
IF OBJECT_ID('tempdb..#configurations3') IS NOT NULL 
        DROP TABLE #configurations3;
create table #configurations3 
(name varchar(100),
minimum varchar(100),
maximum varchar(100),
config_value varchar(100),
run_value varchar(100))

insert into #configurations3 exec master..sp_configure
declare @config_value3 varchar(50)
declare @backupcompress int


select @backupcompress=COUNT(*) from #configurations3 where name='backup compression default'
if @backupcompress=1
select @config_value3=config_value from #configurations3 where name='backup compression default'
if @config_value3=0

BEGIN 

INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            
            SELECT 'Backup compression', config_value ' MB','Backup compression is not configured correctly','Non Compliant' from #configurations3 where name ='backup 

compression default' 

END 
else if @config_value3=1
BEGIN
INSERT  INTO #BlitzResults
            (   Hardening_component,
             Details,
              findings,
              Compliance
            )
           SELECT 'Backup compression', config_value ' MB','Backup compression is configured correctly','Compliant' from #configurations3 where name ='backup 

compression default' 
END

/********SYSTEM DB LOCATION**********/

BEGIN 

INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            
            SELECT top 1 'System db location',SUBSTRING(filename,1,1) +': drive','System db location is not located correctly','Non Compliant' from sysaltfiles where 

dbid =1 and SUBSTRING(filename,1,1)='C'

select @sval=COUNT(*) from #BlitzResults where Hardening_component='System db location'
if @sval=0 
INSERT  INTO #BlitzResults
            (   Hardening_component,
             Details,
              findings,
              Compliance
            )
          SELECT top 1 'System db location',SUBSTRING(filename,1,1)+': drive','System db location is as per compliance','Compliant' from sysaltfiles where dbid =1 
END

/********WINDOWS FIREWALL STATUS**********/
 IF OBJECT_ID('tempdb..#hostnamecompare') IS NOT NULL 
        DROP TABLE #hostnamecompare;

create table #hostnamecompare (returnval nvarchar(max))
exec xp_cmdshell 'hostname >C:\monitoring\serverhostname.txt', no_output 

BULK INSERT #hostnamecompare 
FROM 'C:\monitoring\serverhostname.txt'
WITH
(
ROWTERMINATOR = '\n',DATAFILETYPE='widechar'
)


BEGIN 
INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            
            SELECT  'Hostname and instancename comparision',returnval,'Hostname and instancename are not matching','Non Compliant' from #hostnamecompare where ltrim

(rtrim(returnval))<>@@SERVERNAME

select @sval=COUNT(*) from #BlitzResults where  Hardening_component='Hostname and instancename comparision'
if @sval=0 
INSERT  INTO #BlitzResults
            (   Hardening_component,
             Details,
              findings,
              Compliance
            )
          SELECT 'Hostname and instancename comparision',returnval ,'Hostname and instancename are matching and as per standards','Compliant' from #hostnamecompare 
END

/********MAX DEGREE OF PARALLELISM SETTINGS**********/
IF OBJECT_ID('tempdb..#configurations1') IS NOT NULL 
        DROP TABLE #configurations1;
create table #configurations1 
(name varchar(100),
minimum varchar(100),
maximum varchar(100),
config_value varchar(100),
run_value varchar(100))

insert into #configurations1 exec master..sp_configure

BEGIN 

INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'max degree of parallelism',+ config_value ,'max degree of parallelism is not configured correctly','Non Compliant' from #configurations1 where name 

='max degree of parallelism' and config_value<>1
 
select @sval=COUNT(*) from #BlitzResults where Hardening_component='max degree of parallelism'
if @sval=0 
INSERT  INTO #BlitzResults
            (   Hardening_component,
             Details,
              findings,
              Compliance
            )
           SELECT 'max degree of parallelism', config_value ,'max degree of parallelism is configured correctly','Compliant' from #configurations1 where name ='max 

degree of parallelism'
END

/********Enable optimize for adhoc workload **********/
IF OBJECT_ID('tempdb..#configurations4') IS NOT NULL 
        DROP TABLE #configurations4;
create table #configurations4 
(name varchar(100),
minimum varchar(100),
maximum varchar(100),
config_value varchar(100),
run_value varchar(100))

insert into #configurations4 exec master..sp_configure
declare @config_value4 varchar(50)

BEGIN 

INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'optimize for ad hoc workloads',+ config_value ,'optimize for ad hoc workloads is not configured correctly','Non Compliant' from #configurations4 

where name ='optimize for ad hoc workloads' and config_value<>1
 
select @sval=COUNT(*) from #BlitzResults where Hardening_component='optimize for ad hoc workloads'
if @sval=0 
INSERT  INTO #BlitzResults
            (   Hardening_component,
             Details,
              findings,
              Compliance
            )
           SELECT 'optimize for ad hoc workloads', config_value ,'optimize for ad hoc workloads is configured correctly','Compliant' from #configurations4 where name 

='optimize for ad hoc workloads'
END

/********CHECK SA RENAMING TO SQLADMIN**********/
Declare @saname varchar(200) 
select @saname=name from sys.syslogins where sid=1
if @saname='sa'  
BEGIN 
INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'SA ACCOUNT',+ @saname ,'SA ACCOUNT is not renamed to sqladmin','Non Compliant' 
END
else if @saname='sqladmin'
BEGIN
INSERT  INTO #BlitzResults
            (   Hardening_component,
             Details,
              findings,
              Compliance
            )
            SELECT 'SA ACCOUNT',+ @saname ,'SA ACCOUNT is renamed to sqladmin ','Compliant' 
END

/********CHECK TEMPDB FILES**********/
declare @tempdbfiles int
select @tempdbfiles=count(substring(filename,1,1)) from sys.sysaltfiles where dbid=db_id('tempdb')and groupid <>0
if @tempdbfiles=1  
BEGIN 
INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'TEMPDB FILES',+ @tempdbfiles ,'TEMPDB FILES are not configured as per hardening standards','Non Compliant' 
END
else if @tempdbfiles >1
BEGIN
INSERT  INTO #BlitzResults
            (   Hardening_component,
             Details,
              findings,
              Compliance
            )
            SELECT 'TEMPDB FILES',+ @tempdbfiles ,'TEMPDB FILES are configured as per hardening standards','Compliant' 
END

/********BUILT IN ADMINISTRATORS ACCOUNT**********/
declare @builtinaccount int
select @builtinaccount=COUNT(*) from sys.syslogins where name ='BUILTIN\Administrators'
if @builtinaccount='1'  
BEGIN 
INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'BUILT IN ADMINISTRATORS',+ 'BUILTIN\Administrators' ,'BUILTIN\Administrators account is present on server','Non Compliant' 
END
else if @builtinaccount=0
BEGIN
INSERT  INTO #BlitzResults
            (   Hardening_component,
             Details,
              findings,
              Compliance
            )
            SELECT 'BUILT IN ADMINISTRATORS',+ 'BUILTIN\Administrators' ,'BUILTIN\Administrators account not present on server','Compliant' 
END

/********nagios login for checkmk**********/
declare @nagioslogin int
select @nagioslogin=COUNT(*) from sys.syslogins where name ='nagios_mk'
if @nagioslogin='1'  
BEGIN 
INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'Check_mk login',+ 'nagios_mk' ,'nagios_mk login is present on server','Compliant' 
END
else if @nagioslogin=0
BEGIN
INSERT  INTO #BlitzResults
            (   Hardening_component,
             Details,
              findings,
              Compliance
            )
            SELECT 'Check_mk login',+ 'nagios_mk' ,'nagios_mk login not present on server','Non Compliant' 
END

/********SQL AGENT JOBS **********/
Declare @jobname int
select @jobname=count(*) from msdb..sysjobs where name ='DBCC ChekDB'
if @jobname='1'  
BEGIN 
INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'SQLAGENTJOB:DBCC ChekDB',+ 'DBCC ChekDB' ,'DBCC ChekDB job found on server','Compliant' 
END
else
BEGIN 
INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'SQLAGENTJOB:DBCC ChekDB',+ 'DBCC ChekDB' ,'DBCC ChekDB job not found on server','Non Compliant' 
END

select @jobname=count(*) from msdb..sysjobs where name ='backup_status_report'
if @jobname='1'  
BEGIN 
INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'SQLAGENTJOB:backup_status_report',+ 'backup_status_report' ,'backup_status_report job found on server','Compliant' 
END
else
BEGIN 
INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'SQLAGENTJOB:backup_status_report',+ 'backup_status_report' ,'backup_status_report job not found on server','Non Compliant' 
END
select @jobname=count(*) from msdb..sysjobs where name ='Failed_Job_Status'
if @jobname='1'  
BEGIN 
INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'SQLAGENTJOB:Failed_Job_Status',+ 'Failed_Job_Status' ,'Failed_Job_Status job found on server','Compliant' 
END
else
BEGIN 
INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'SQLAGENTJOB:Failed_Job_Status',+ 'Failed_Job_Status' ,'Failed_Job_Status job not found on server','Non Compliant' 
END
select @jobname=count(*) from msdb..sysjobs where name ='Long_running_query'
if @jobname='1'  
BEGIN 
INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'SQLAGENTJOB:Long_running_query',+ 'Long_running_query' ,'Long_running_query job found on server','Compliant' 
END
else
BEGIN 
INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'SQLAGENTJOB:Long_running_query',+ 'Long_running_query' ,'Long_running_query job not found on server','Non Compliant' 
END
select @jobname=count(*) from msdb..sysjobs where name ='sp_cycle_errorlog'
if @jobname='1'  
BEGIN 
INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'SQLAGENTJOB:sp_cycle_errorlog',+ 'sp_cycle_errorlog' ,'sp_cycle_errorlog found on server','Compliant' 
END
else
BEGIN 
INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'SQLAGENTJOB:sp_cycle_errorlog',+ 'sp_cycle_errorlog' ,'sp_cycle_errorlog job not found on server','Non Compliant' 
END
select @jobname=count(*) from msdb..sysjobs where name ='Log Space Alert'
if @jobname='1'  
BEGIN 
INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'SQLAGENTJOB:Log Space Alert',+ 'Log Space Alert' ,'Log Space Alert job found on server','Compliant' 
END
else
BEGIN 
INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'SQLAGENTJOB:Log Space Alert',+ 'Log Space Alert' ,'DBCC ChekDB job not found on server','Non Compliant' 
END
select @jobname=count(*) from msdb..sysjobs where name ='Database Growth Report'
if @jobname='1'  
BEGIN 
INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'SQLAGENTJOB:Database Growth Report',+ 'Database Growth Report' ,'Database Growth Report job found on server','Compliant' 
END
else
BEGIN 
INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'SQLAGENTJOB:Database Growth Report',+ 'Database Growth Report' ,'Database Growth Report job not found on server','Non Compliant' 
END
select @jobname=count(*) from msdb..sysjobs where name ='DB_Growth_Mail_Every_friday'
if @jobname='1'  
BEGIN 
INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'SQLAGENTJOB:DB_Growth_Mail_Every_friday',+ 'DB_Growth_Mail_Every_friday' ,'DB_Growth_Mail_Every_friday job  found on server','Compliant' 
END
else
BEGIN 
INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'SQLAGENTJOB:DB_Growth_Mail_Every_friday',+ 'DB_Growth_Mail_Every_friday' ,'DB_Growth_Mail_Every_friday jon not found on server','Non Compliant' 
END
select @jobname=count(*) from msdb..sysjobs where name ='DB_Reindex'
if @jobname='1'  
BEGIN 
INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'SQLAGENTJOB:DB_Reindex',+ 'DB_Reindex' ,'DB_Reindex job found on server','Compliant' 
END
else
BEGIN 
INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'SQLAGENTJOB:DB_Reindex',+ 'DB_Reindex' ,'DB_Reindex job not found on server','Non Compliant' 
END
select @jobname=count(*) from msdb..sysjobs where name ='Schema_Change_History'
if @jobname='1'  
BEGIN 
INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'SQLAGENTJOB:Schema_Change_History',+ 'Schema_Change_History' ,'Schema_Change_History job found on server','Compliant' 
END
else
BEGIN 
INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'SQLAGENTJOB:Schema_Change_History',+ 'Schema_Change_History' ,'Schema_Change_History job not found on server','Non Compliant' 
END
select @jobname=count(*) from msdb..sysjobs where name ='Table_Growth_Analysis'
if @jobname='1'  
BEGIN 
INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'SQLAGENTJOB:Table_Growth_Analysis',+ 'Table_Growth_Analysis' ,'Table_Growth_Analysis job found on server','Compliant' 
END
else
BEGIN 
INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'SQLAGENTJOB:Table_Growth_Analysis',+ 'Table_Growth_Analysis' ,'Table_Growth_Analysis job not found on server','Non Compliant' 
END
select @jobname=count(*) from msdb..sysjobs where name ='Update_statistics'
if @jobname='1'  
BEGIN 
INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'SQLAGENTJOB:Update_statistics',+ 'Update_statistics' ,'Update_statistics job found on server','Compliant' 
END
else
BEGIN 
INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'SQLAGENTJOB:Update_statistics',+ 'Update_statistics' ,'Update_statistics job not found on server','Non Compliant' 
END
select @jobname=count(*) from msdb..sysjobs where name ='System_database_backup'
if @jobname='1'  
BEGIN 
INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'SQLAGENTJOB:System_database_backup',+ 'System_database_backup' ,'System_database_backup job found on server','Compliant' 
END
else
BEGIN 
INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'SQLAGENTJOB:System_database_backup',+ 'System_database_backup' ,'System_database_backup job not found on server','Non Compliant' 
END
select @jobname=count(*) from msdb..sysjobs where name ='DBA_VLF_COUNT'
if @jobname='1'  
BEGIN 
INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'SQLAGENTJOB:DBA_VLF_COUNT',+ 'DBA_VLF_COUNT' ,'DBA_VLF_COUNT job found on server','Compliant' 
END
else
BEGIN 
INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'SQLAGENTJOB:DBA_VLF_COUNT',+ 'DBA_VLF_COUNT' ,'DBA_VLF_COUNT job not found on server','Non Compliant' 
END
select @jobname=count(*) from msdb..sysjobs where name ='DBA_Failed_Backup_Status'
if @jobname='1'  
BEGIN 
INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'SQLAGENTJOB:DBA_Failed_Backup_Status',+ 'DBA_Failed_Backup_Status' ,'DBA_Failed_Backup_Status job found on server','Compliant' 
END
else
BEGIN 
INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'SQLAGENTJOB:DBA_Failed_Backup_Status',+ 'DBA_Failed_Backup_Status' ,'DBA_Failed_Backup_Status job not found on server','Non Compliant' 
END
select @jobname=count(*) from msdb..sysjobs where name ='Long_running_query_from_management_studio'
if @jobname='1'  
BEGIN 
INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'SQLAGENTJOB:Long_running_query_from_management_studio',+ 'Long_running_query_from_management_studio' ,'Long_running_query_from_management_studio 

job found on server','Compliant' 
END
else
BEGIN 
INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'SQLAGENTJOB:Long_running_query_from_management_studio',+ 'Long_running_query_from_management_studio' ,'Long_running_query_from_management_studio 

job not found on server','Non Compliant' 
END
select @jobname=count(*) from msdb..sysjobs where name ='Deadlock Information'
if @jobname='1'  
BEGIN 
INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'SQLAGENTJOB:Deadlock Information',+ 'Deadlock Information' ,'Deadlock Information job found on server','Compliant' 
END
else
BEGIN 
INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'SQLAGENTJOB:Deadlock Information',+ 'Deadlock Information' ,'Deadlock Information job not found on server','Non Compliant' 
END
select @jobname=count(*) from msdb..sysjobs where name ='DBA_Failed_Login_Attempts'
if @jobname='1'  
BEGIN 
INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'SQLAGENTJOB:DBA_Failed_Login_Attempts',+ 'DBA_Failed_Login_Attempts' ,'DBA_Failed_Login_Attempts job found on server','Compliant' 
END
else
BEGIN 
INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'SQLAGENTJOB:DBA_Failed_Login_Attempts',+ 'DBA_Failed_Login_Attempts' ,'DBA_Failed_Login_Attempts job not found on server','Non Compliant' 
END
select @jobname=count(*) from msdb..sysjobs where name ='Transaction_log_backup'
if @jobname='1'  
BEGIN 
INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'SQLAGENTJOB:Transaction_log_backup',+ 'Transaction_log_backup' ,'Transaction_log_backup job found on server','Compliant' 
END
else
BEGIN 
INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'SQLAGENTJOB:Transaction_log_backup',+ 'Transaction_log_backup' ,'Transaction_log_backup job not found on server','Non Compliant' 
END
select @jobname=count(*) from msdb..sysjobs where name ='FTP_Serverinfo'
if @jobname='1'  
BEGIN 
INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'SQLAGENTJOB:FTP_Serverinfo',+ 'FTP_Serverinfo' ,'FTP_Serverinfo job found on server','Compliant' 
END
else
BEGIN 
INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'SQLAGENTJOB:FTP_Serverinfo',+ 'FTP_Serverinfo' ,'FTP_Serverinfo job not found on server','Non Compliant' 
END
select @jobname=count(*) from msdb..sysjobs where name ='DBA_IO_ERROR_NOTIFICATION'
if @jobname='1'  
BEGIN 
INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'SQLAGENTJOB:DBA_IO_ERROR_NOTIFICATION',+ 'DBA_IO_ERROR_NOTIFICATION' ,'DBA_IO_ERROR_NOTIFICATION job found on server','Compliant' 
END
else
BEGIN 
INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'SQLAGENTJOB:DBA_IO_ERROR_NOTIFICATION',+ 'DBA_IO_ERROR_NOTIFICATION' ,'DBA_IO_ERROR_NOTIFICATION job not found on server','Non Compliant' 
END
select @jobname=count(*) from msdb..sysjobs where name ='User_database_backup'
if @jobname='1'  
BEGIN 
INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'SQLAGENTJOB:User_database_backup',+ 'User_database_backup' ,'User_database_backup job found on server','Compliant' 
END
else
BEGIN 
INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'SQLAGENTJOB:User_database_backup',+ 'User_database_backup' ,'User_database_backup job not found on server','Non Compliant' 
END
select @jobname=count(*) from msdb..sysjobs where name ='DBA_Database_state'
if @jobname='1'  
BEGIN 
INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'SQLAGENTJOB:DBA_Database_state',+ 'DBA_Database_state' ,'DBA_Database_state job found on server','Compliant' 
END
else
BEGIN 
INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'SQLAGENTJOB:DBA_Database_state',+ 'DBA_Database_state' ,'DBA_Database_state job not found on server','Non Compliant' 
END
select @jobname=count(*) from msdb..sysjobs where name ='Process_tracking'
if @jobname='1'  
BEGIN 
INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'SQLAGENTJOB:Process_tracking',+ 'Process_tracking' ,'Process_tracking job found on server','Compliant' 
END
else
BEGIN 
INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'SQLAGENTJOB:Process_tracking',+ 'Process_tracking' ,'Process_tracking job not found on server','Non Compliant' 
END
select @jobname=count(*) from msdb..sysjobs where name ='DBA_Auto_growth_settings'
if @jobname='1'  
BEGIN 
INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'SQLAGENTJOB:Process_tracking',+ 'DBA_Auto_growth_settings' ,'DBA_Auto_growth_settings job found on server','Compliant' 
END
else
BEGIN 
INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'SQLAGENTJOB:Process_tracking',+ 'DBA_Auto_growth_settings' ,'DBA_Auto_growth_settings job not found on server','Non Compliant' 
END


IF OBJECT_ID('tempdb..#server_monitoring') IS NOT NULL 
        DROP TABLE #server_monitoring;
create table #server_monitoring (info nvarchar(max))
exec xp_cmdshell 'schtasks.exe/query >C:\monitoring\server_monitoring.txt', no_output 

BULK INSERT #server_monitoring 
FROM 'C:\monitoring\server_monitoring.txt'
WITH
(
ROWTERMINATOR = '\n'
)

declare @server_monitoring int 
select @server_monitoring=COUNT(*) from #server_monitoring where info like '%server_monitoring%'

if @server_monitoring=1  
BEGIN 
INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'Task Schedule:Server_monitoring',+ 'server_monitoring' ,'Server_monitoring schedule task is found server','Compliant' 
END
else if @server_monitoring=0
BEGIN
INSERT  INTO #BlitzResults
            (   Hardening_component,
             Details,
              findings,
              Compliance
            )
            SELECT 'Task Schedule:Server_monitoring',+ 'server_monitoring' ,'Server_monitoring schedule task is not found server','Non Compliant' 
END

declare @perfmon_report int 
select @perfmon_report=COUNT(*) from #server_monitoring where info like '%perfmon_report%'
print @perfmon_report
if @perfmon_report=1  
BEGIN 
INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'Task Schedule:perfmon_report',+ 'perfmon_report' ,'perfmon_report schedule task is found server','Compliant' 
END
else if @perfmon_report=0
BEGIN
INSERT  INTO #BlitzResults
            (   Hardening_component,
             Details,
              findings,
              Compliance
            )
            SELECT 'Task Schedule:perfmon_report',+ 'perfmon_report' ,'perfmon_report schedule task is not found server','Non Compliant' 
END

IF OBJECT_ID('tempdb..#perfmoncollection') IS NOT NULL 
DROP TABLE #perfmoncollection;
        
create table #perfmoncollection (returnval nvarchar(max))
exec xp_cmdshell 'logman query >C:\monitoring\perfmoncollection.txt', no_output 

BULK INSERT #perfmoncollection 
FROM 'C:\monitoring\perfmoncollection.txt'
WITH
(
ROWTERMINATOR = '\n'
)


    DELETE FROM #perfmoncollection WHERE returnval IS NULL
    DELETE FROM #perfmoncollection WHERE returnval LIKE '%Data Collector Set%'
    DELETE FROM #perfmoncollection WHERE returnval LIKE '%The command completed successfully.%'

Declare @perfmoncollection varchar(100)
select @perfmoncollection=returnval from #perfmoncollection where returnval like '%sql_perfmon%'
if @perfmoncollection like '%sql_perfmon%'

BEGIN 
INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'Perfmon collection',+ 'sql_perfmon' ,'sql_perfmon schedule is found server','Compliant' 
END
else if @perfmoncollection not like '%sql_perfmon%'
BEGIN
INSERT  INTO #BlitzResults
            (   Hardening_component,
             Details,
              findings,
              Compliance
            )
            SELECT 'Perfmon collection',+ 'sql_perfmon' ,'sql_perfmon schedule task is not found server','Non Compliant' 
END

BEGIN 
INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'Auto Growth ',DB_NAME(dbid) ,'auto growth not set for file '+ filename ,'Non Compliant' from master..sysaltfiles where growth=10
END

select @sval=COUNT(*) from #BlitzResults where Hardening_component ='Auto Growth '
if @sval=0
BEGIN
INSERT  INTO #BlitzResults
            (   Hardening_component,
             Details,
              findings,
              Compliance
            )
           SELECT 'Auto Growth ', 'all databases' ,'auto growth set for all files' ,'Compliant'
END

IF OBJECT_ID('tempdb..#pagefilesize') IS NOT NULL 
DROP TABLE #pagefilesize;

create table #pagefilesize (returnval nvarchar(max))
exec xp_cmdshell 'wmic pagefile list /format:list >C:\monitoring\pagefilesize.txt', no_output 

BULK INSERT #pagefilesize 
FROM 'C:\monitoring\pagefilesize.txt'
WITH
(
ROWTERMINATOR = '\n',DATAFILETYPE='widechar'
)

Declare @pagefilesize int
declare @phymem int

IF OBJECT_ID('tempdb..#mem_info') IS NOT NULL 
DROP TABLE #mem_info;
create table #mem_info
(
index1 int,
name1 varchar(250),
internalvalue varchar(250),
char_value varchar(250)
)

insert into #mem_info exec xp_msver


select @phymem=cast(round(internalvalue,0) as int)*.88  from #mem_info where name1='PhysicalMemory'


select @pagefilesize=sum(convert(int,substring(returnval,19,LEN(returnval)-18))) from #pagefilesize  where returnval like 'AllocatedBaseSize=%'


 if @phymem >= 4095 and @pagefilesize <= 4095 
BEGIN 

INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'Page file setttings',+ 'page file size:'+ convert(varchar,@pagefilesize) + ' MB' ,'Page file setttings is not configured correctly','Non Compliant' 
 
END 
else 
BEGIN
INSERT  INTO #BlitzResults
            (   Hardening_component,
             Details,
              findings,
              Compliance
            )
            SELECT 'Page file setttings',+ 'page file size:'+ convert(varchar,@pagefilesize)+ ' MB' ,'Page file setttings is configured correctly','Compliant' 
END

IF OBJECT_ID('tempdb..#tcpotimization') IS NOT NULL 
DROP TABLE #tcpotimization;

create table #tcpotimization (returnval nvarchar(max))
exec xp_cmdshell 'netsh int tcp show global >C:\monitoring\tcpotimization.txt', no_output 

BULK INSERT #tcpotimization 
FROM 'C:\monitoring\tcpotimization.txt'
WITH
(
ROWTERMINATOR = '\n',DATAFILETYPE='widechar'
)

Declare @TCP_RSS varchar(100)

select @TCP_RSS=substring(returnval,39,LEN(returnval)-38) from #tcpotimization  where returnval like 'Receive-Side Scaling State%'
IF @TCP_RSS='disabled'
BEGIN 
INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'TCP_OPTIMIZATION',+ 'Receive-Side Scaling State' ,'Receive-Side Scaling State is configured correctly','Compliant' 
END 
else 
BEGIN
INSERT  INTO #BlitzResults
            (   Hardening_component,
             Details,
              findings,
              Compliance
            )
           SELECT 'TCP_OPTIMIZATION',+ 'Receive-Side Scaling State' ,'Receive-Side Scaling State is not configured correctly','Non Compliant' 
END

Declare @TCP_Chimney varchar(100)

select @TCP_Chimney=substring(returnval,39,LEN(returnval)-38) from #tcpotimization  where returnval like 'Chimney Offload State%'
IF @TCP_Chimney='disabled'
BEGIN 
INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'TCP_OPTIMIZATION',+ 'Chimney Offload State' ,'Chimney Offload State is configured correctly','Compliant' 
END 
else 
BEGIN
INSERT  INTO #BlitzResults
            (   Hardening_component,
             Details,
              findings,
              Compliance
            )
           SELECT 'TCP_OPTIMIZATION',+ 'Chimney Offload State' ,'Chimney Offload State is not configured correctly','Non Compliant' 
END

Declare @TCP_AUTO_TUNING varchar(100)

select @TCP_AUTO_TUNING=substring(returnval,39,LEN(returnval)-38) from #tcpotimization  where returnval like 'Receive Window Auto-Tuning Level%'
IF @TCP_AUTO_TUNING='disabled'
BEGIN 
INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'TCP_OPTIMIZATION',+ 'Receive Window Auto-Tuning Level' ,'Receive Window Auto-Tuning Level is configured correctly','Compliant' 
END 
else 
BEGIN
INSERT  INTO #BlitzResults
            (   Hardening_component,
             Details,
              findings,
              Compliance
            )
           SELECT 'TCP_OPTIMIZATION',+ 'Receive Window Auto-Tuning Level' ,'Receive Window Auto-Tuning Level is not configured correctly','Non Compliant' 
END
IF OBJECT_ID('tempdb..#chartprogram') IS NOT NULL 
DROP TABLE #chartprogram;

create table #chartprogram (returnval nvarchar(max))
exec xp_cmdshell 'dir "C:\Program Files\PAL\PAL\pal.ps1" >C:\monitoring\chartprogram.txt', no_output 

BULK INSERT #chartprogram 
FROM 'C:\monitoring\chartprogram.txt'
WITH
(
ROWTERMINATOR = '\n',DATAFILETYPE='widechar'
)

Declare @chartprogram varchar(100)

select @chartprogram=COUNT(*) from #chartprogram  where returnval like 'File Not Found%'
IF @chartprogram=0
BEGIN 
INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'PAL PROGRAM',+ @chartprogram ,'PAL Program is installed on the server','Compliant' 
END 
ELSE  
BEGIN
INSERT  INTO #BlitzResults
            (   Hardening_component,
             Details,
              findings,
              Compliance
            )
             SELECT 'PAL PROGRAM',+ @chartprogram ,'PAL Program is not installed on the server','Non Compliant' 
END

IF OBJECT_ID('tempdb..#chartprogram1') IS NOT NULL 
DROP TABLE #chartprogram1;

create table #chartprogram1 (returnval nvarchar(max))
exec xp_cmdshell 'dir "C:\Program Files (x86)\Microsoft Chart Controls\Assemblies\System.Windows.Forms.DataVisualization.dll" >C:\monitoring\chartprogram1.txt', 

no_output 

BULK INSERT #chartprogram1 
FROM 'C:\monitoring\chartprogram1.txt'
WITH
(
ROWTERMINATOR = '\n',DATAFILETYPE='widechar'
)



select @chartprogram=COUNT(*) from #chartprogram1  where returnval like 'File Not Found%'
IF @chartprogram=0
BEGIN 
INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'MICROSOFT CHART PROGRAM',+ @chartprogram ,'MICROSOFT CHART Program is installed on the server','Compliant' 
END 
ELSE  
BEGIN
INSERT  INTO #BlitzResults
            (   Hardening_component,
             Details,
              findings,
              Compliance
            )
             SELECT 'MICROSOFT CHART PROGRAM',+ @chartprogram ,'MICROSOFT CHART Program is not installed on the server','Non Compliant' 
END

BEGIN 

INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'Antivirus Exclusions', data ,'Antivirus Exclusions are configured correctly','Compliant' from #SQLREGVALUES where value ='Antivirusprofile' and 

data like '%mdf%'

select @sval=COUNT(*) from #BlitzResults where Hardening_component='Antivirus Exclusions' and Details like '%mdf%'
if @sval=0
INSERT  INTO #BlitzResults
            (   Hardening_component,
             Details,
              findings,
              Compliance
            )
           SELECT 'Antivirus Exclusions','mdf' ,'Antivirus Exclusions are not configured correctly','Non Compliant' 
END

BEGIN 

INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'Antivirus Exclusions', data ,'Antivirus Exclusions are configured correctly','Compliant' from #SQLREGVALUES where value ='Antivirusprofile' and 

data like'%ldf%'
select @sval=COUNT(*) from #BlitzResults where Hardening_component='Antivirus Exclusions' and Details Like'%ldf%'
if @sval=0
INSERT  INTO #BlitzResults
            (   Hardening_component,
             Details,
              findings,
              Compliance
            )
           SELECT 'Antivirus Exclusions','ldf' ,'Antivirus Exclusions are not configured correctly','Non Compliant' 
END

BEGIN 

INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'Antivirus Exclusions', data ,'Antivirus Exclusions are configured correctly','Compliant' from #SQLREGVALUES where value ='Antivirusprofile' and 

data like'%ndf%'
select @sval=COUNT(*) from #BlitzResults where Hardening_component='Antivirus Exclusions' and Details Like'%ndf%'
if @sval=0
INSERT  INTO #BlitzResults
            (   Hardening_component,
             Details,
              findings,
              Compliance
            )
           SELECT 'Antivirus Exclusions','ndf' ,'Antivirus Exclusions are not configured correctly','Non Compliant' 
END

BEGIN 

INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'Antivirus Exclusions', data ,'Antivirus Exclusions are configured correctly','Compliant' from #SQLREGVALUES where value ='Antivirusprofile' and 

data like'%4|11|bak%'
select @sval=COUNT(*) from #BlitzResults where Hardening_component='Antivirus Exclusions' and Details like'%4|11|bak%'
if @sval=0
INSERT  INTO #BlitzResults
            (   Hardening_component,
             Details,
              findings,
              Compliance
            )
           SELECT 'Antivirus Exclusions','bak' ,'Antivirus Exclusions are not configured correctly','Non Compliant' 
END

BEGIN 

INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'Antivirus Exclusions', data ,'Antivirus Exclusions are configured correctly','Compliant' from #SQLREGVALUES where value ='Antivirusprofile' and 

data like'%trn%'
select @sval=COUNT(*) from #BlitzResults where Hardening_component='Antivirus Exclusions' and Details like'%trn%'
if @sval=0
INSERT  INTO #BlitzResults
            (   Hardening_component,
             Details,
              findings,
              Compliance
            )
           SELECT 'Antivirus Exclusions','trn' ,'Antivirus Exclusions are not configured correctly','Non Compliant' 
END

BEGIN 

INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'Antivirus Exclusions', data ,'Antivirus Exclusions are configured correctly','Compliant' from #SQLREGVALUES where value ='Antivirusprofile' and 

data like '%\Program Files%'
select @sval=COUNT(*) from #BlitzResults where Hardening_component='Antivirus Exclusions' and Details like '%Program Files%'
if @sval=0
INSERT  INTO #BlitzResults
            (   Hardening_component,
             Details,
              findings,
              Compliance
            )
           SELECT 'Antivirus Exclusions','%Program Files%' ,'Antivirus Exclusions are not configured correctly','Non Compliant' 
END

BEGIN 

INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'Database Mail Profile', data ,'Database Mail Profile is configured correctly','Compliant' from #SQLREGVALUES where value ='DatabaseMailProfile' and 

data ='NMSQLDBA'
select @sval=COUNT(*) from #BlitzResults where Hardening_component='Database Mail Profile' and Details ='NMSQLDBA'
if @sval=0
INSERT  INTO #BlitzResults
            (   Hardening_component,
             Details,
              findings,
              Compliance
            )
           SELECT 'Database Mail Profile','NMSQLDBA' ,'Database Mail Profile is not configured correctly','Non Compliant' 
END


BEGIN 

INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'MSSQL Audit Level', data=
            CASE data
         WHEN '1' THEN 'None'
         WHEN '2' THEN 'Failed logins Only'
         WHEN '3' THEN 'Both Failed and Successful logins'
         WHEN '4' THEN 'Successful logins Only'
         END,'MSSQL Audit Level is configured correctly','Compliant' from #SQLREGVALUES where value ='AuditLevel' and data ='2'
select @sval=COUNT(*) from #BlitzResults where Hardening_component='MSSQL Audit Level' and Details ='2'
if @sval=0
INSERT  INTO #BlitzResults
            (   Hardening_component,
             Details,
              findings,
              Compliance
            )
           SELECT 'MSSQL Audit Level',data =
           CASE data
         WHEN '1' THEN 'None'
         WHEN '2' THEN 'Failed logins Only'
         WHEN '3' THEN 'Both Failed and Successful logins'
         WHEN '4' THEN 'Successful logins Only'
         END,'MSSQL Audit Level is not configured correctly','Non Compliant' from #SQLREGVALUES where value ='AuditLevel' and data <>'2'
END


BEGIN 

INSERT  INTO #BlitzResults
            ( Hardening_component,
              Details,
              findings,
              Compliance
            )
            SELECT 'MSSQL Login Mode', data=
            CASE data
         WHEN '1' THEN 'Windows Authontication Mode'
         WHEN '2' THEN 'SQL and Windows Authontication Mode'
         END,'MSSQL Login Mode is configured correctly','Compliant' from #SQLREGVALUES where value ='LoginMode' and data ='2'
select @sval=COUNT(*) from #BlitzResults where Hardening_component='MSSQL Login Mode' and Details ='2'
if @sval=0
INSERT  INTO #BlitzResults
            (   Hardening_component,
             Details,
              findings,
              Compliance
            )
           SELECT 'MSSQL Login Mode', data=
            CASE data
         WHEN '1' THEN 'Windows Authontication Mode'
         WHEN '2' THEN 'SQL and Windows Authontication Mode'
         END,'MSSQL Login Mode is not configured correctly','Non Compliant' from #SQLREGVALUES where value ='LoginMode' and data <>'2'
END

BEGIN 
 IF OBJECT_ID('tempdb..#public2') IS NOT NULL 
        DROP TABLE #public2;
create table #public2 (dbname sysname,puser varchar(100),permission varchar (100))

insert into #public2 SELECT 'model',prin.[name] [User], sec.state_desc + ' ' + sec.permission_name [Permission]
FROM model.[sys].[database_permissions] sec
  JOIN model.[sys].[database_principals] prin
    ON sec.[grantee_principal_id] = prin.[principal_id]
WHERE sec.class = 0 
ORDER BY [User], [Permission];

insert into #BlitzResults ( Hardening_component,Details,findings) SELECT 'Guest User Permission On Model Database', puser ,permission from #public2
           if (select COUNT(*) from  #BlitzResults where Findings ='GRANT CONNECT' and Details='guest' and Hardening_component ='Guest User Permission On Model 

Database')>0
           update #BlitzResults set Compliance ='Non Compliant' where Findings ='GRANT CONNECT' and Hardening_component ='Guest User Permission On Model Database'  and Details='guest'
           else
           --update #BlitzResults set Compliance ='Compliant',  Findings ='Database has no Guest access' where Findings is NULL  and Hardening_component ='Master & Msdb Database Public rights' 
           delete #BlitzResults where Hardening_component ='Guest User Permission On Model Database'
           insert into #BlitzResults ( Hardening_component,Details,findings,Compliance) SELECT 'Guest User Permission On Model Database', 'Guest','No Guest user on Model database','compliant'
END

BEGIN 
 IF OBJECT_ID('tempdb..#public') IS NOT NULL 
        DROP TABLE #public;
create table #public (dbnmae sysname,pobject varchar (200), puser varchar(50),permission varchar(100) )

insert into #public SELECT 'master', 'master'+'.'+Obj.name AS object,Us.name AS username,dp.permission_name AS permission 
FROM master.sys.database_permissions dp
JOIN master.sys.sysusers Us 
ON dp.grantee_principal_id = Us.uid 
right JOIN master.sys.sysobjects Obj
ON dp.major_id = Obj.id --where Us.name='public'
where Obj.name  in('xp_dirtree',
'xp_getnetname', 
'xp_msver',
'xp_fixeddrives',
'xp_sscanf', 
'xp_sprintf', 
'spt_fallback_db',
'spt_fallback_dev', 
'spt_fallback_usg',
'spt_monitor', 
'spt_values')
insert into #public SELECT 'msdb', 'msdb'+'.'+Obj.name AS object,Us.name AS username,dp.permission_name AS permission 
FROM msdb.sys.database_permissions dp
JOIN msdb.sys.sysusers Us 
ON dp.grantee_principal_id = Us.uid 
right JOIN msdb.sys.sysobjects Obj
ON dp.major_id = Obj.id --where Us.name='public'
where Obj.name  in(
'backupfile', 
'backupmediafamily', 
'backupmediaset',
'backupset', 
'logmarkhistory', 
'restorefile', 
'restorefilegroup', 
'restorehistory', 
'suspect_pages')


insert into #BlitzResults ( Hardening_component,Details,findings) SELECT 'Master & Msdb Database Public rights', pobject ,puser from #public
            update #BlitzResults set Compliance ='Non Compliant' where Findings ='public' and Hardening_component ='Master & Msdb Database Public rights'
            update #BlitzResults set Compliance ='Compliant',  Findings ='Object has no Public access' where (Findings is NULL or Findings ='NULL') and 

Hardening_component ='Master & Msdb Database Public rights'

END



BEGIN 

IF @@VERSION NOT LIKE '%Microsoft SQL Server 2000%'
AND @@VERSION NOT LIKE '%Microsoft SQL Server 2005%'
AND @@VERSION NOT LIKE '%Microsoft SQL Server 2008 (%'
BEGIN
 IF OBJECT_ID('tempdb..#public1') IS NOT NULL 
        DROP TABLE #public1;
create table #public1 (Servicename varchar(100),startup_type_desc varchar (200), service_account varchar(100))

insert into #public1 SELECT  servicename,startup_type_desc,service_account FROM sys.dm_server_services where servicename not like '%SQL Full-text %'
insert into #BlitzResults ( Hardening_component,Details,findings) SELECT 'MSSQL Services Startup', servicename ,startup_type_desc from #public1
            update #BlitzResults set Compliance ='Non Compliant' where Findings <> 'autometic' and Hardening_component ='MSSQL Services Startup'
            update #BlitzResults set Compliance ='Compliant' where Findings ='Automatic' and Hardening_component ='MSSQL Services Startup'

IF OBJECT_ID('tempdb..#public222') IS NOT NULL 
DROP TABLE #public222;
create table #public222 (Servicename varchar(100),startup_type_desc varchar (200), service_account varchar(100))			
insert into #public222 SELECT  servicename,startup_type_desc,service_account FROM sys.dm_server_services where servicename not like '%SQL Full-text %'
insert into #BlitzResults ( Hardening_component,Details,findings) SELECT 'MSSQL Services Account', servicename ,service_account from #public222
            --update #BlitzResults set Compliance ='Non Compliant' where Findings like '%LocalSystem%' and Hardening_component ='MSSQL Services Account'
			--update #BlitzResults set Compliance ='Non Compliant' where Findings like '%NT Service\MSSQLSERVER%' and Hardening_component ='MSSQL Services Account'
			--update #BlitzResults set Compliance ='Non Compliant' where Findings like '%NT Service\SQLSERVERAGENT%' and Hardening_component ='MSSQL Services Account'
            update #BlitzResults set Compliance ='Compliant' where (Findings not like '%LocalSystem%' or Findings not like '%NT Service%' or  Findings not like '%NT 

Service%')  and Hardening_component ='MSSQL Services Account'
			update #BlitzResults set Compliance ='Non Compliant' where (Findings like '%NT Service\SQLSERVERAGENT%' or Findings like '%NT Service

\MSSQLSERVER%' or Findings like '%LocalSystem%' ) and Hardening_component ='MSSQL Services Account'

 IF OBJECT_ID('tempdb..#public21') IS NOT NULL 
        DROP TABLE #public21;
create table #public21 (Servicename varchar(100),startup_type_desc varchar (200), service_account varchar(100),is_clustered varchar(10) )

insert into #public21 SELECT  servicename,startup_type_desc,service_account,is_clustered FROM sys.dm_server_services where is_clustered='Y'
insert into #BlitzResults ( Hardening_component,Details,findings) SELECT 'MSSQL Services Startup', servicename ,startup_type_desc from #public21
if (SELECT count(*) FROM sys.dm_server_services where is_clustered='Y' )>0
begin
update #BlitzResults set Compliance ='Compliant' where Findings ='manual' and Hardening_component ='MSSQL Services Startup' 
end 

END
END

BEGIN 

DECLARE @tmp TABLE(col1 varchar(128));
DECLARE @osversion varchar(500);

INSERT @tmp
EXEC xp_cmdshell 'wmic os get Name';

SELECT @osversion=  SUBSTRING(col1, 1, PATINDEX('%|%', col1)-1) 
FROM @tmp
WHERE col1 NOT LIKE '%Name%' AND col1 LIKE '%[A-Z]%';


IF @osversion NOT LIKE '%Microsoft Windows Server 2003%'

BEGIN

IF OBJECT_ID('tempdb..#FAU_SIZE') IS NOT NULL 
        DROP TABLE #FAU_SIZE;

create table #FAU_SIZE (returnval nvarchar(max))
exec xp_cmdshell 'C:\monitoring\perfmon_reports\File_allocation_unit.bat >C:\monitoring\perfmon_reports\file_allocation_unit.txt', no_output 

BULK INSERT #FAU_SIZE 
FROM 'C:\monitoring\perfmon_reports\file_allocation_unit.txt'
WITH
(
ROWTERMINATOR = '\n',DATAFILETYPE='widechar'
)

if (select COUNT(*) from #FAU_SIZE where returnval is not null and returnval not like 'C:\%' and returnval not like '\\%'
and returnval not like '--%' and returnval not like 'Name%' and returnval not like '%65536%'  )>0
Begin
insert into #BlitzResults ( Hardening_component,Details,findings,Compliance)
select 'File Allocation Unit',returnval,'Drive is not having 64K File Allocation unit size','Non Compliant' from #FAU_SIZE where returnval is not null and returnval 

not like 'C:\%' and returnval not like '\\%'
and returnval not like '--%' and returnval not like 'Name%' and returnval not like '%65536%' 
end 
else
Begin
insert into #BlitzResults ( Hardening_component,Details,findings,Compliance)
select 'File Allocation Unit',returnval,'Drive is having 64K File Allocation unit size','Compliant' from #FAU_SIZE where returnval is not null and returnval not 

like 'C:\%' and returnval not like '\\%'
and returnval not like '--%' and returnval not like 'Name%' 
End
END
END

select * from #BlitzResults order by compliance desc
  
GO
PRINT ''
PRINT ''
exec master..sp_configure 'show advanced options',1
reconfigure with override
GO
declare @config_value1 varchar(50)
select @config_value1=config_value from #xconfigurations where name ='xp_cmdshell'

if @config_value1 = 0
exec master..sp_configure 'xp_cmdshell',0
reconfigure with override
GO

exec master..sp_configure 'show advanced options',0
reconfigure with override
GO

