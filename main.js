const acme = require('acme-client');
const archiver = require('archiver');
const crypto = require('crypto');
const aws = require('aws-sdk');
const process = require('process');
const { v4: uuidv4 } = require('uuid');
const { verifyAccessToken, getUserHash } = require('homegames-common');
const { X509Certificate } = require('crypto');


const AWS_ROUTE_53_HOSTED_ZONE_ID = process.env.AWS_ROUTE_53_HOSTED_ZONE_ID;

// lol i should delete this
const authenticate = (username, token) => new Promise((resolve, reject) => {
	verifyAccessToken(username, token).then(resolve).catch(reject);
});

const getLinkRecord = (name, throwOnEmpty) => new Promise((resolve, reject) => {
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
            reject(err);
        } else {
            for (const i in data.ResourceRecordSets) {
                const entry = data.ResourceRecordSets[i];
                if (entry.Name === name + '.') {
                    resolve(entry.ResourceRecords[0].Value);
                }
            }
            throwOnEmpty ? reject() : resolve(null);
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
    getLinkRecord(name, true).then(() => {
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

const getDnsStatus = (publicIp) => new Promise((resolve, reject) => {
    getLinkRecord(getUserHash(publicIp) + '.homegames.link').then(dnsRecord => {
        resolve(dnsRecord);
    }).catch(err => {
        console.error('error getting dns record');
        console.error(err);
    });
});

const requestCert = (publicIp) => new Promise((resolve, reject) => {
    console.log('need to do the thing');
    getCertStatus(publicIp).then(certInfo => {
        console.log('dsfsdfdsfdsfsdf');
        console.log(certInfo);
//        getDnsStatus(userId, localServerIp).then(recordExists => {

            if (certInfo.certData && certInfo.certExpiration && certInfo.certExpiration > Date.now()) {
                reject('A valid cert has already been created for this IP (' + publicIp + ').  If you do not have access to your private key, reach out to support@homegames.io to generate a new one');
            } else {
                acme.crypto.createPrivateKey().then(key => {
                    const requestId = generateId();
                    acme.crypto.createCsr({
                        commonName: getUserHash(publicIp) + '.homegames.link'
                    }).then(([certKey, certCsr]) => {
                        const lambda = new aws.Lambda({
                            region: 'us-west-2'
                        });
    
                        console.log('about to invoke');
                        lambda.invoke({
                            FunctionName: 'cert-doer',
                            Payload: JSON.stringify({csr: certCsr, key, requestId, publicIp }),
                            InvocationType: 'Event'
                        }, (err, data) => {
                            console.log("ERROR AND DATA");
                            console.log(err);
                            console.log(data);
                            resolve({requestId, key: certKey.toString()});
                        });
                    });
                });
            }
        });
    //});
});

const certExists = (ip) => new Promise((resolve, reject) => {
    const ddb = new aws.DynamoDB({
        region: 'us-west-2'
    });

    const certParams = {
        TableName: 'hg_certs',
        Key: {
            'developer_id': {
                S: ip, 
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

const getCert = (ip) => new Promise((resolve, reject) => {
    const ddb = new aws.DynamoDB({
        region: 'us-west-2'
    });

    const certParams = {
        TableName: 'hg_certs',
        Key: {
            'developer_id': {
                S: ip
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
    const certString = Buffer.from(certData, 'base64').toString();
    console.log('cert string!!');
    console.log(certString);
    const { validTo } = new X509Certificate(certString);
    console.log("CERT OBJEFFE");
    console.log(validTo);
    resolve(new Date(validTo).getTime());
});

const getCertStatus = (ip) => new Promise((resolve, reject) => {
    let body = {
        certFound: false,
        certExpiration: null,
        certIp: ip,
        dnsAlias: null
    };

    certExists(ip).then((exists) => {
        if (exists) {
            body.certFound = true;
            getCert(ip).then(certData => {
                body.certData = certData;
                getCertExpiration(certData).then(certExpiration => {
                    body.certExpiration = certExpiration;
                    getDnsStatus(ip).then(record => {
                        body.dnsAlias = record && record === ip ? `${getUserHash(ip)}.homegames.link`: null;
                        resolve(body);
                    });
                }).catch(err => {
                    console.error('Error getting cert expiration info');
                    console.error(err);
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
    const publicIp = event.requestContext?.identity?.sourceIp;

    console.log("PUBLIC IP");
    console.log(publicIp);

    if (event.httpMethod === 'POST' && event.path === '/cert_status') {
        const authToken = event && event.headers['hg-token'];
        const username = event && event.headers['hg-username'];

        let body = '';
        //if (false && !authToken || !username) {
        //    body = 'Requires username and auth token';
        //} else {
            //let userId;
            //try {
            //    userId = await authenticate(username, authToken);
            //} catch (err) { 
            //    return {
            //        statusCode: 400,
            //        body: 'Bad auth token'
            //    }
            //}

            const reqBody = event.body ? JSON.parse(event.body) : null;
//            const localServerIp = reqBody && reqBody.localServerIp;
// 
//            if (!localServerIp) {
//                return {
//                    statusCode: 400,
//                    body: 'Missing localServerIp for cert status'
//                }
//            }
//            console.log("AYYYYYY SERVER LOCAL UOP " + event.localServerIp);
            body = await getCertStatus(publicIp);
        //}
        return {
            statusCode: 200,
            body: JSON.stringify(body)
        }
    } else {

        //const authToken = event && event.headers['hg-token'];
        //const username = event && event.headers['hg-username'];

        let body = '';
        //if (!authToken || !username) {
        //    body = 'Requires username and auth token';
        //} else {
        //    let userId;
        //    try {
        //        userId = await authenticate(username, authToken);
        //    } catch (err) { 
        //        return {
        //            statusCode: 400,
        //            body: 'Bad auth token'
        //        }
        //    }

            if (event.path === '/update_dns') {
                //const reqBody = event.body ? JSON.parse(event.body) : null;
                //const sourceIp = reqBody && reqBody.ip;

                if (publicIp) {
                    // todo: support multiple instances 
                    console.log('updating with source ip ' + publicIp);
                    await updateLinkRecord(getUserHash(publicIp) + '.homegames.link', publicIp);
                    body = 'updated dns record to ' + publicIp;
                }
            } else {

                const reqBody = event.body ? JSON.parse(event.body) : null;
//                const localServerIp = reqBody && reqBody.localServerIp;
 
//                if (!localServerIp) {
//                    return {
//                        statusCode: 400,
//                        body: 'Missing localServerIp for cert'
//                    }
//                }
 
                let certData = '';
                try {
                    certData = await requestCert(publicIp);
                } catch (err) {
                    console.error('Error requesting cert');
                    console.error(err);
                    return {
                        statusCode: 500,
                        body: err
                    }
                }

                body = await getCertZip(certData);

                return {
                    statusCode: 200,
                    isBase64Encoded: true,
                    body
                };

//                body = JSON.stringify();
           // }
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
