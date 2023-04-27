const acme = require('acme-client');
const crypto = require('crypto');
const aws = require('aws-sdk');
const process = require('process');
const { v4: uuidv4 } = require('uuid');
const { verifyAccessToken, getUserHash } = require('homegames-common');

const AWS_ROUTE_53_HOSTED_ZONE_ID = process.env.AWS_ROUTE_53_HOSTED_ZONE_ID;

// lol i should delete this
const authenticate = (username, token) => new Promise((resolve, reject) => {
	verifyAccessToken(username, token).then(resolve).catch(reject);
});

const getDnsRecord = (name) => new Promise((resolve, reject) => {
    const params = {
        HostedZoneId: AWS_ROUTE_53_HOSTED_ZONE_ID,
        StartRecordName: name,
        StartRecordType: 'TXT'
    };

    const route53 = new aws.Route53();
    route53.listResourceRecordSets(params, (err, data) => {
        if (err) {
            console.error('error listing record sets');
            console.error(err);
            reject();
        } else {
            for (const i in data.ResourceRecordSets) {
                const entry = data.ResourceRecordSets[i];
                if (entry.Name === name + '.') {
                    resolve(entry.ResourceRecords[0].Value);
                }
            }
            reject();
        }
    });

});

const deleteDnsRecord = (name) => new Promise((resolve, reject) => {

    getDnsRecord(name).then((value) => {
        const deleteDnsParams = {
            ChangeBatch: {
                Changes: [
                    {
                        Action: 'DELETE',
                        ResourceRecordSet: {
                            Name: name,//dnsChallengeRecord.Name,
                            Type: 'TXT',
                            TTL: 300,
                            ResourceRecords: [
                                {
                                    Value: value,//dnsChallengeRecord.Value
                                }
                            ]
                            //                        TTL: 300,
                            //                        Type: dnsChallengeRecord.Type
                        }
                    }
                ]
            },
            HostedZoneId: AWS_ROUTE_53_HOSTED_ZONE_ID
        };

        const route53 = new aws.Route53();
        route53.changeResourceRecordSets(deleteDnsParams, (err, data) => {
            console.log('fkdkfskdfkdsf');
            console.log(err);
            console.log(data);
            const deleteParams = {
                Id: data.ChangeInfo.Id
            };

            route53.waitFor('resourceRecordSetsChanged', deleteParams, (err, data) => {
                if (data.ChangeInfo.Status === 'INSYNC') {
                    resolve();
                }
            });

        });
    }).catch(err => {
        console.error('Error');
        console.error(err);
        reject(err);
    });

});

const createDnsRecord = (name, value) => new Promise((resolve, reject) => {
    const dnsParams = {
        ChangeBatch: {
            Changes: [
                {
                    Action: 'CREATE',
                    ResourceRecordSet: {
                        Name: name,
                        ResourceRecords: [
                            {
                                Value: '"' + value + '"'
                            }
                        ],
                        TTL: 300,
                        Type: 'TXT'
                    }
                }
            ]
        },
        HostedZoneId: AWS_ROUTE_53_HOSTED_ZONE_ID
    };

    const route53 = new aws.Route53();
    route53.changeResourceRecordSets(dnsParams, (err, data) => {
        if (err) {
            reject(err);
        } else {
            const params = {
                Id: data.ChangeInfo.Id
            };

            route53.waitFor('resourceRecordSetsChanged', params, (err, data) => {
                if (data.ChangeInfo.Status === 'INSYNC') {
                    resolve();
                }
            });
        }
    });

});

const challengeCreateFn = async(authz, challenge, keyAuthorization) => {
    if (challenge.type === 'dns-01') {
        console.log('creating!!');
        await createDnsRecord(`_acme-challenge.${authz.identifier.value}`, keyAuthorization);
    }
};

const challengeRemoveFn = async(authz, challenge, keyAuthorization) => {

    if (challenge.type === 'dns-01') {
        console.log('removing!!');
        await deleteDnsRecord(`_acme-challenge.${authz.identifier.value}`);
    }
};

const getHash = (input) => {
    return crypto.createHash('md5').update(input).digest('hex');
};

const generateId = () => getHash(uuidv4());

const updateRequestRecord = (userId, requestId, certificate) => new Promise((resolve, reject) => {
    const ddb = new aws.DynamoDB({
        region: 'us-west-2'
    });

    const updateParams = {
        TableName: 'cert_requests',
        Key: {
            'developer_id': {
                S: userId
            },
            'request_id': {
                S: requestId 
            }
        },
        AttributeUpdates: {
            'certificate': {
                Action: 'PUT',
                Value: {
                    S: certificate 
                }
            }
        }
    };

    ddb.updateItem(updateParams, (err, putResult) => {
        if (err) {
            console.error('error updating cert request');
            console.error(err);
            reject();
        } else {
            resolve();
        }
    });
});

const createRequestRecord = (userId, localServerIp, requestId) => new Promise((resolve, reject) => {
    const client = new aws.DynamoDB({
        region: 'us-west-2'
    });
    const params = {
        TableName: 'cert_requests',
        Item: {
            'developer_id': {
                S: userId 
            },
            'request_id': {
                S: requestId
            },
            'date_created': {
                N: Date.now() + ''
            },
            'local_server_ip': {
                S: localServerIp
            }
        }
    };

    client.putItem(params, (err, putResult) => {
        if (!err) {
            resolve();
        } else {
            reject(err);
        }
    });
});

const getExistingCertRequests = (userId) => new Promise((resolve, reject) => {
    const readClient = new aws.DynamoDB.DocumentClient({
        region: 'us-west-2'
    });

    const params = {
        TableName: 'cert_requests',
        ScanIndexForward: false,
        KeyConditionExpression: '#developer_id = :developer_id',
        ExpressionAttributeNames: {
            '#developer_id': 'developer_id',
        },
        ExpressionAttributeValues: {
            ':developer_id': userId
        }
    };

    readClient.query(params, (err, results) => {
        if (err) {
            console.log(err);
            reject(err.toString());
        } else {
            resolve(results.Items);
        }
    });
 
});

const generateCert = (userId, requestId, key, csr, localServerIp) => new Promise((resolve, reject) => {
    getExistingCertRequests(userId).then(certRequests => {
        console.log('existing cert requests ? ');
        console.log(certRequests);
        createRequestRecord(userId, localServerIp, requestId).then(() => {
            console.log('creating one in prod really');
            const client = new acme.Client({
                directoryUrl: acme.directory.letsencrypt.production,//staging,//production,//.staging
                accountKey: key
            });

//            acme.crypto.createCsr({
//                commonName: getUserHash(userId) + '.homegames.link'//,
//            }).then(([certKey, certCsr]) => {
                console.log('did this !!');
                const autoOpts = {
            	    csr,
            	    email: 'joseph@homegames.io',
            	    termsOfServiceAgreed: true,
                        challengeCreateFn,//: async (authz, challenge, keyAuthorization) => {},
                        challengeRemoveFn,//: async (authz, challenge, keyAuthorization) => {},
            	    challengePriority: ['dns-01']
                };

                client.auto(autoOpts).then(certificate => {
                    console.log('certificate!');
                    console.log(certificate);
                    updateRequestRecord(userId, requestId, certificate).then(resolve);
                }).catch(err => {
                    console.error('error creating certificate');
                    console.error(err);
                });
 //           }).catch(err => {
   //             console.error('error creating csr');
     //           console.error(err);
       //         reject(err);
         //   });
        });
    });
 
});
exports.handler = async(event) => {
    console.log('event');
    console.log(event);
    
    let body = 'what the heck';

    if (event && event.key) {
        body = await generateCert(event.userId, event.requestId, event.key, event.csr,event.localServerIp);
    }

    const response = {
        statusCode: 200,
        body
    };

    return response;
};


