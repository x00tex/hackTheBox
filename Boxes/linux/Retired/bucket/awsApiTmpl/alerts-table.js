// create table
var params = {
    TableName: 'alerts',
    KeySchema: [
        {
            AttributeName: 'title',
            KeyType: 'HASH'
        }
    ],
    AttributeDefinitions: [
        {
            AttributeName: 'title',
            AttributeType: 'S'
        }
    ],
    ProvisionedThroughput: {
        ReadCapacityUnits: 10,
        WriteCapacityUnits: 5,
    },
};

dynamodb.createTable(params, function(err, data) {
    if (err) ppJson(err); // an error occurred
    else ppJson(data); // successful response

});

//put items
var params = {
    TableName: 'alerts',
    Item: {
      "data": "<pd4ml:attachment description=\"attached.txt\" icon=\"PushPin\">file:///root/root.txt</pd4ml:attachment>",
      "title": "Ransomware"
    },  
};

docClient.put(params, function(err, data) {
    if (err) ppJson(err); // an error occurred
    else ppJson(data); // successful response
});

//scan table
var params = {
    TableName: 'alerts',
    ReturnConsumedCapacity: 'TOTAL',
};
dynamodb.scan(params, function(err, data) {
    if (err) ppJson(err); // an error occurred
    else ppJson(data); // successful response
});
