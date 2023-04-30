const acme = require('acme-client');
const archiver = require('archiver');
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
        TableName: 'hg_certs',
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
        TableName: 'hg_certs',
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

const getCertZip = (certData) => new Promise((resolve, reject) => {
    const archive = archiver('zip', {
        zlib: { level: 9 } // Sets the compression level.
    });
    
    const bufs = [];
    archive.on('data', (buf) => {
        bufs.push(buf);
    });

    archive.on('end', () => {
        const totalBuf = Buffer.from(Buffer.concat(bufs));
        resolve(totalBuf.toString('base64'));
    });

    archive.append(certData.key, { name: 'hg-certs/homegames.key' });

    archive.finalize();
});

const requestCert = (userId, authToken, localServerIp) => new Promise((resolve, reject) => {
    console.log('need to do the thing');
    getCertInfo(userId, authToken).then(certInfo => {
    acme.crypto.createPrivateKey().then(key => {
        const requestId = generateId();
        acme.crypto.createCsr({
            commonName: getUserHash(userId + localServerIp) + '.homegames.link'//,
        }).then(([certKey, certCsr]) => {
            const lambda = new aws.Lambda({
                region: 'us-west-2'
            });

            console.log('about to invoke');
            lambda.invoke({
                FunctionName: 'cert-doer',
                Payload: JSON.stringify({csr: certCsr, key, userId, requestId,localServerIp}),
                InvocationType: 'Event'
            }, (err, data) => {
                console.log("ERROR AND DATA");
                console.log(err);
                console.log(data);
                resolve({requestId, key: certKey.toString()});
            });
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

const certExists = (username, ip) => new Promise((resolve, reject) => {
    const ddb = new aws.DynamoDB({
        region: 'us-west-2'
    });

    const certParams = {
        TableName: 'hg_certs',
        Key: {
            'developer_id': {
                S: username
            },
            'ip_address': {
                S: ip
            }
        }
    };

    ddb.getItem(certParams, (err, data) => {
        if (err) {
            console.log('error getting that');
            console.log(err);
            reject();
        } else {
            console.log('here is dataaa');
            console.log(data);
            resolve(!!data.Item);
        }
    });

});

const getCert = (username, ip) => new Promise((resolve, reject) => {
    const ddb = new aws.DynamoDB({
        region: 'us-west-2'
    });

    const certParams = {
        TableName: 'hg_certs',
        Key: {
            'developer_id': {
                S: username
            },
            'ip_address': {
                S: ip
            }
        }
    };

    ddb.getItem(certParams, (err, data) => {
        if (err) {
            console.log('error getting that');
            console.log(err);
            reject();
        } else {
            if (data.Item.certificate) {
                resolve(Buffer.from(data.Item.certificate.S).toString('base64'));
            } else {
                resolve(null);
            }
        }
    });


});

const getCertExpiration = (certData) => new Promise((resolve, reject) => {
    resolve('todo!');
});

const getCertStatus = (username, ip) => new Promise((resolve, reject) => {
    let body = {
        certFound: false,
        certExpiration: null,
        certIp: ip
    };

    certExists(username, ip).then((exists) => {
        if (exists) {
            body.certFound = true;
            getCert(username, ip).then(certData => {
                body.certData = certData;
                getCertExpiration(certData).then(certExpiration => {
                    body.certExpiration = certExpiration;
                    resolve(body);
                });
            });
        } else {
            resolve(body);
        }
    });
});

const getExistingCertRequests = (userId) => new Promise((resolve, reject) => {
    const readClient = new aws.DynamoDB.DocumentClient({
        region: 'us-west-2'
    });

    const params = {
        TableName: 'hg_certs',
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

exports.handler = async(event) => {
    console.log('event what the hell');
    console.log(event);

    if (event.httpMethod === 'POST' && event.path === '/cert_status') {
        const authToken = event && event.headers['hg-token'];
        const username = event && event.headers['hg-username'];

        let body = '';
        if (!authToken || !username) {
            body = 'Requires username and auth token';
        } else {
            let userId;
            try {
                userId = await authenticate(username, authToken);
            } catch (err) { 
                return {
                    statusCode: 400,
                    body: 'Bad auth token'
                }
            }

            const reqBody = event.body ? JSON.parse(event.body) : null;
            const localServerIp = reqBody && reqBody.localServerIp;
 
            if (!localServerIp) {
                return {
                    statusCode: 400,
                    body: 'Missing localServerIp for cert status'
                }
            }
            console.log("AYYYYYY SERVER LOCAL UOP " + event.localServerIp);
            body = await getCertStatus(username, localServerIp);
        }
        return {
            statusCode: 200,
            body: JSON.stringify(body)
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

                if (sourceIp) {
                    // todo: support multiple instances 
                    console.log('updating with source ip ' + sourceIp);
                    await updateLinkRecord(getUserHash(username) + '.homegames.link', sourceIp);
                    body = 'updated dns record to ' + sourceIp;
                }
            } else {

                const reqBody = event.body ? JSON.parse(event.body) : null;
                const localServerIp = reqBody && reqBody.localServerIp;
 
                if (!localServerIp) {
                    return {
                        statusCode: 400,
                        body: 'Missing localServerIp for cert'
                    }
                }
 
                const certData = await requestCert(username, authToken, localServerIp);

                body = await getCertZip(certData);

                return {
                    statusCode: 200,
                    isBase64Encoded: true,
                    body
                };

//                body = JSON.stringify();
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
