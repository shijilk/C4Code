-- PKs Tables without Primary Keys

select schema_name(tab.schema_id) as [schema_name], 
    tab.[name] as table_name
from sys.tables tab
    left outer join sys.indexes pk
        on tab.object_id = pk.object_id 
        and pk.is_primary_key = 1
where pk.object_id is null
order by schema_name(tab.schema_id),
    tab.[name]

-- Need to consider columns that are candidates for primary Key
-- Also need to check whether there are clustered index in these tables