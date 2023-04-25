const acme = require('acme-client');
const crypto = require('crypto');
const aws = require('aws-sdk');
const process = require('process');
const { v4: uuidv4 } = require('uuid');
const { verifyAccessToken } = require('homegames-common');

const AWS_ROUTE_53_HOSTED_ZONE_ID = process.env.AWS_ROUTE_53_HOSTED_ZONE_ID;


const getUserHash = (username) => {
    console.log('getting user hash for user ' + username);
    if (!username) {
        reject('missing username');
    }
    return crypto.createHash('md5').update(username).digest('hex');
};

// lol i should delete this
const authenticate = (username, token) => new Promise((resolve, reject) => {
	verifyAccessToken(username, token).then(resolve).catch(reject);
});

const getLinkRecord = (name) => new Promise((resolve, reject) => {
    const params = {
        HostedZoneId: AWS_ROUTE_53_HOSTED_ZONE_ID,
        StartRecordName: name,
        StartRecordType: 'A'
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

const updateLinkRecord = (name, value) => new Promise((resolve, reject) => {
    getLinkRecord(name).then(() => {
        changeLinkRecord(name, value).then(resolve); 
    }).catch(err => {
        const dnsParams = {
            ChangeBatch: {
                Changes: [
                    {
                        Action: 'CREATE',
                        ResourceRecordSet: {
                            Name: name,
                            ResourceRecords: [
                                {
                                    Value: value
                                }
                            ],
                            TTL: 60,
                            Type: 'A'
                        }
                    }
                ]
            },
            HostedZoneId: AWS_ROUTE_53_HOSTED_ZONE_ID
        };
        
        console.log('dns params');
        console.log(dnsParams);

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

});

const changeLinkRecord = (name, value) => new Promise((resolve, reject) => {
    const dnsParams = {
        ChangeBatch: {
            Changes: [
                {
                    Action: 'UPSERT',
                    ResourceRecordSet: {
                        Name: name,
                        ResourceRecords: [
                            {
                                Value: value
                            }
                        ],
                        TTL: 60,
                        Type: 'A'
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

const createRequestRecord = (userId, requestId) => new Promise((resolve, reject) => {
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

const requestCert = (userId) => new Promise((resolve, reject) => {
    console.log('need to do the thing');
    acme.crypto.createPrivateKey().then(key => {
        const requestId = generateId();

        const lambda = new aws.Lambda({
            region: 'us-west-2'
        });

        console.log('about to invoke');
        lambda.invoke({
            FunctionName: 'cert-doer',
            Payload: JSON.stringify({key, userId, requestId}),
            InvocationType: 'Event'
        }, (err, data) => {
            console.log("ERROR AND DATA");
            console.log(err);
            console.log(data);
            resolve({requestId, key: key.toString()});
        });

//        createRequestRecord(userId, requestId).then(() => {
//            const client = new acme.Client({
//                directoryUrl: acme.directory.letsencrypt.staging,//production,//.staging
//                accountKey: key
//            });
//
//            acme.crypto.createCsr({
//                commonName: 'picodeg.io'//,
//            //          altNames: ['picodeg.io']
//            }).then(([certKey, certCsr]) => {
//                console.log('did this');
//                console.log(certKey);
//                console.log(certCsr);
//                const autoOpts = {
//            	    csr: certCsr,
//            	    email: 'joseph@homegames.io',
//            	    termsOfServiceAgreed: true,
//                        challengeCreateFn,//: async (authz, challenge, keyAuthorization) => {},
//                        challengeRemoveFn,//: async (authz, challenge, keyAuthorization) => {},
//            	    challengePriority: ['dns-01']
//                };
//
//                client.auto(autoOpts).then(certificate => {
//                    console.log('certificate!');
//                    console.log(certificate);
//                    updateRequestRecord(userId, requestId, certificate);
//                }).catch(err => {
//                    console.error('error creating certificate');
//                    console.error(err);
//                });
//            }).catch(err => {
//                console.error('error creating csr');
//                console.error(err);
//                reject(err);
//            });
//        });
    });
});

exports.handler = async(event) => {
    console.log('event what the hell');
    console.log(event);

    if (event.httpMethod === 'GET') {
        if (event.path === '/cert_status') {
            return {
                statusCode: 200,
                body: 'ayy lmao cert status'
            }
 
        } 
        return {
            statusCode: 200,
            body: 'ayy lmao'
        }
    } else {

        const authToken = event && event.headers['hg-token'];
        const username = event && event.headers['hg-username'];

        let body = '';
        if (!authToken || !username) {
            body = 'Requires username and auth token';
        } else {
            const userId = await authenticate(username, authToken);
            if (event.path === '/update_dns') {
                const reqBody = event.body ? JSON.parse(event.body) : null;
                const sourceIp = reqBody && reqBody.ip;
                //const sourceIp = event.requestContext.identity && event.requestContext.identity.sourceIp;

                if (sourceIp) {
                    // todo: support multiple instances 
                    console.log('updating with source ip ' + sourceIp);
                    await updateLinkRecord(getUserHash(username) + '.homegames.link', sourceIp);
                    body = 'updated dns record to ' + sourceIp;
                }
            } else {
                body = JSON.stringify(await requestCert(username));
            }
        }

        const response = {
            statusCode: 200,
            body
        };

        return response;
    }
};

//requestCert('123').then(res => {
//    console.log('got res!');
//    console.log(res);
//});
