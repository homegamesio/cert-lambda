const aws = require('aws-sdk');

const lambda = new aws.Lambda({region: 'us-west-2'});

lambda.invoke({InvocationType: 'Event', FunctionName: 'cert-doer', Payload: JSON.stringify({ayy: 'lmao does this work what about now'})}, (err, data) => {
    console.log(err);
    console.log(data);
});
