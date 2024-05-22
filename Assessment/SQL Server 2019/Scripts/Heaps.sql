SELECT SCHEMA_NAME(schema_id) AS [SchemaName],
[Tables].name AS [TableName],
SUM([Partitions].[rows]) AS [TotalRowCount]
FROM sys.tables AS [Tables]
JOIN sys.partitions AS [Partitions]
ON [Tables].[object_id] = [Partitions].[object_id]
AND [Partitions].index_id IN ( 0, 1 )
join sys.indexes I
on i.object_id=Tables.object_id
where i.type=0
GROUP BY SCHEMA_NAME(schema_id), [Tables].name
order by TotalRowCount desc;

-- Gives us a list of tables where no Clusterd Index is there.
-- Need to check the Select operation vs other DML operations on these tables.