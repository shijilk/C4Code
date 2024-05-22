/* 
   Confirm the Database Mail account and profile is configured correctly 
*/ 

DECLARE @DatabaseMail VARCHAR(255);  

SELECT   
    ProfileName = smp.name  
    ,AccountName = sma.name  
    ,AccountFromAddress = sma.email_address  
    ,AccountReplyTo = sma.replyto_address  
    ,SMTPServer = sms.servername  
    ,SMTPPort = sms.port  
FROM msdb.dbo.sysmail_account sma  
    INNER JOIN msdb.dbo.sysmail_profileaccount smpa ON sma.account_id = smpa.account_id  
    INNER JOIN msdb.dbo.sysmail_profile smp ON smpa.profile_id = smp.profile_id  
    INNER JOIN msdb.dbo.sysmail_server sms ON sma.account_id = sms.account_id;

/*  
    Confirm SQL Server Agent is configured to use Database Mail correctly  
*/  
DECLARE @res TABLE  
(  
    Value VARCHAR(255)  
    , Data VARCHAR(255)  
);  
INSERT INTO @res  
EXEC master.dbo.xp_instance_regread N'HKEY_LOCAL_MACHINE', N'SOFTWARE\Microsoft\MSSQLServer\SQLServerAgent', N'UseDatabaseMail';  
INSERT INTO @res  
EXEC master.dbo.xp_instance_regread N'HKEY_LOCAL_MACHINE', N'SOFTWARE\Microsoft\MSSQLServer\SQLServerAgent', N'DatabaseMailProfile';  
IF (  
        SELECT COUNT(*)  
        FROM @res r  
        WHERE r.Value = 'UseDatabaseMail' AND r.Data = 1  
    ) = 1 AND   
    (  
        SELECT COUNT(*)  
        FROM @res r  
        WHERE r.Value = 'DatabaseMailProfile' AND r.Data IS NOT NULL  
    ) = 1  
SET @DatabaseMail = 'Configured'  
ELSE  
SET @DatabaseMail = 'Not Configured';  

select @DatabaseMail AS [DB_Mail_Configured_Or_Not]




