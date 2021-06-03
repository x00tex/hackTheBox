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
