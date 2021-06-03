var params = {
    TableName: 'users',
    ReturnConsumedCapacity: 'TOTAL',
};
dynamodb.scan(params, function(err, data) {
    if (err) ppJson(err); // an error occurred
    else ppJson(data); // successful response
});