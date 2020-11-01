
const crypto = require('crypto');
const net = require("net");
const ECDHCrypto = require('ecdh-crypto');


//第一个包的包头部分
//Client Hello 包
const pskHeader = Buffer.from([0x16, 0xf1, 0x03 /*固定部分*/, 0x00, 0xd4 /* 212 后面内容大小*/, 0x00, 0x00, 0x00, 0xd0 /* 208 后面内容大小*/, 0x01, 0x03, 0xf1 /*版本号*/, 0x01, 0xc0, 0x2b]);
//第一个公钥的头信息
const clientPubHead = Buffer.from([0x00, 0x00, 0x00, 0xa2, 0x01, 0x00, 0x00, 0x00, 0x9d, 0x00, 0x10, 0x02, 0x00, 0x00, 0x00, 0x47, 0x00, 0x00, 0x00, 0x01, 0x00, 0x41]);
//第二个公钥的头信息
const secondPublicHead = Buffer.from([0x00, 0x00, 0x00, 0x47, 0x00, 0x00, 0x00, 0x02, 0x00, 0x41]);
//包结尾信息
const pskTail = Buffer.from([0x00, 0x00, 0x00, 0x01]);
//心跳包数据
const heartBeartData =Buffer.from([0x00, 0x00, 0x00, 0x10, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0xff, 0xff, 0xff, 0xff]);

function SplitServerFinishData(serverFinishData){
    var packItems = new Array();
    var offset = 0;
    while(offset < serverFinishData.length) {
        //数据长度，不包括5字节的头部
        var len = serverFinishData.readInt16BE(offset+3);
        var data = Buffer.allocUnsafe(len);
        serverFinishData.copy(data,0,offset+5,offset+5+len);
        var head = Buffer.allocUnsafe(5);
        serverFinishData.copy(head,0,offset,offset+5);
        packItems.push({"data":data, "head":head});
        offset += 5+len;
    }

    return packItems;
}

function HkdfExpand(key, message,outLen){
    var result = Buffer.alloc(0);
    var count  = Math.ceil( outLen / 32);
    for (let index = 1; index <= count; index++) {
        const hmac = crypto.createHmac('sha256', key);
        var tmp = Buffer.concat([message, Buffer.from([index])]);
        tmp = Buffer.concat([result, tmp]);
        hmac.update(tmp);
        result = Buffer.concat([result, hmac.digest()]);
    }
    console.log('扩展秘钥:');
    console.log(Bytes2HexString(result));
    return result.slice(0,outLen);
}


function GetNonce(data , seq) {
    var result = Buffer.alloc(data.length);
    data.copy(result,0);
    result[result.length-1] = result[result.length-1] ^ seq;
    return result;
}

function Int32ToBytes(value){
    var result = Buffer.alloc(4);
    result.writeInt32BE(value, 0);
    return result;
}

function Int16ToBytes(value){
    var result = Buffer.alloc(2);
    result.writeInt16BE(value, 0);
    return result;
}

function AesGcmEncrypt(key, nonce, aad ,data){
    const encipher = crypto.createCipheriv('aes-128-gcm',key,nonce);
    encipher.setAAD(aad);
    var cipherText = encipher.update(data);
    encipher.final();
    var tag = encipher.getAuthTag();
    return Buffer.concat([cipherText,tag]);
}

function AesGcmDecrypt(key, nonce, aad ,data){   
    const decipher = crypto.createDecipheriv('aes-128-gcm', key, nonce);  
    decipher.setAuthTag(data.slice(data.length-16));
    decipher.setAAD(aad); 
    var result1 = decipher.update(data.slice(0,data.length-16));
    var result2 = decipher.final();
    return Buffer.concat([result1,result2]);
}

function HmacHash256(key,data){
    const hmac = crypto.createHmac('sha256', key);
    hmac.update(data);
    return hmac.digest();
}



const Hexstring2btye = (str)=> {
    let pos = 0;
    let len = str.length;
    if (len % 2 != 0) {
        return null;
    }
    len /= 2;
    let hexA = new Array();
    for (let i = 0; i < len; i++) {
        let s = str.substr(pos, 2);
        let v = parseInt(s, 16);
        hexA.push(v);
        pos += 2;
    }
    return hexA;
}

const Bytes2HexString = (b)=> {
    let result = "";
    for (let i = 0; i < b.length; i++) {
        let hex = (b[i]).toString(16);
        if (hex.length === 1) {
            hex = '0' + hex;
        }
        result += hex.toUpperCase();
    }
    return result;
}

function Hash256Final(data){
    var sha256Hash = crypto.createHash('sha256');
    sha256Hash.update(data);
    return sha256Hash.digest();
}

class Tls1_3{
    constructor(){
        this.servSeq_ = 1;
        this.clientSeq_=1;
        this.dataHkdf_ = Buffer.allocUnsafe(0);
        this.hashData_ = Buffer.allocUnsafe(0);
        this.privateKey_ = Buffer.allocUnsafe(0);
        this.pskReqData_ = Buffer.allocUnsafe(0);
    }
    
    BuildPskRequest(){
        try {
        //包长217字节
        var offset = 0;
        this.pskReqData_ = Buffer.alloc(217);
        //第一个步：  拷贝psk 头
        pskHeader.copy(this.pskReqData_,offset);
        offset += pskHeader.length;
        //32 字节随机数
        var clientRandom = crypto.randomBytes(32);
        clientRandom.copy(this.pskReqData_,offset);
        offset += clientRandom.length;
        //4字节时间戳
        var timeSpan = Math.floor(Date.now() / 1000);
        this.pskReqData_.writeInt32BE(timeSpan,offset);
        offset +=4;
        //加入公钥头信息
        clientPubHead.copy(this.pskReqData_,offset);
        offset += clientPubHead.length;
        //生成两对公私钥
        var keyPair1 = ECDHCrypto.createECDHCrypto('P-256');
        var keyPair2 = ECDHCrypto.createECDHCrypto('P-256');
        //组包2个公钥
        keyPair1.publicCodePoint.copy(this.pskReqData_,offset);
        offset += keyPair1.publicCodePoint.length;
        ////第二个公钥的头信息
        secondPublicHead.copy(this.pskReqData_,offset);
        offset += secondPublicHead.length;
        
        //第二个公钥
        keyPair2.publicCodePoint.copy(this.pskReqData_,offset);
        offset += keyPair2.publicCodePoint.length;

        //包的结尾信息
        pskTail.copy(this.pskReqData_,offset);
        offset += pskTail.length;
        this.privateKey_ = keyPair1.d;
        return this.pskReqData_;
        } catch (error) {
            
        }   
    }


    //服务器返回4段数据 16 f1 03 开头，后面两个字节的长度
     HandleServerFinish(serverFinishData){
         try {
            var packItems = SplitServerFinishData(serverFinishData);
            if(packItems.length == 0){
                console.log('分割服务器数据失败');
                return;
            }
            var serverPubKey = serverFinishData.slice(0x3f,0x80);
            console.log('服务器公钥:');
            console.log(Bytes2HexString(serverPubKey));
            //开始协商秘钥
            var ecdh = crypto.createECDH("prime256v1");
            ecdh.setPrivateKey(this.privateKey_);
            var secretKey=  ecdh.computeSecret(serverPubKey);
            console.log('第一次协商出来的秘钥:');
            console.log(Bytes2HexString(secretKey));

            //hash256 源数据
            var hash256Source = secretKey;
            secretKey = Hash256Final(hash256Source);

            console.log('SHA 256 Hash 之后的秘钥:');
            console.log(Bytes2HexString(secretKey));
            //计算sha256
            hash256Source = Buffer.concat([this.pskReqData_.slice(5),packItems[0].data]);
            var hashRet = Hash256Final(hash256Source);
            //秘钥扩展，扩展出56 字节的秘钥
            var hkdfRet = HkdfExpand(secretKey,Buffer.concat([Buffer.from('handshake key expansion'), Buffer.from(hashRet)]), 56);
            //10 开始 Aes_Gcm Decrypt 解密
            var aesKey = hkdfRet.slice(0x10,0x20);
            var nonce = GetNonce(hkdfRet.slice(0x2c), this.servSeq_);
            var aesAad = Buffer.concat([Buffer.from([0x00, 0x00, 0x00, 0x00]) ,Int32ToBytes(this.servSeq_)]);
            aesAad = Buffer.concat([aesAad, packItems[1].head]);
            var plainText = AesGcmDecrypt(aesKey,nonce,aesAad,packItems[1].data);
            console.log('解密服务器返回的第二部分数据:');
            console.log(Bytes2HexString(plainText));
    
            //step 11 把解密结果压hash缓冲区
            hash256Source = Buffer.concat([hash256Source,plainText]);
            this.servSeq_++;
            nonce = GetNonce(hkdfRet.slice(0x2c), this.servSeq_);
            aesAad = Buffer.concat([Buffer.from([0x00, 0x00, 0x00, 0x00]) ,Int32ToBytes(this.servSeq_)]);
            aesAad = Buffer.concat([aesAad, packItems[2].head]);
            plainText  =  AesGcmDecrypt(aesKey,nonce,aesAad,packItems[2].data);
            console.log('解密服务器返回的第三部分数据:');
            console.log(Bytes2HexString(plainText));
    
            //解密第四部分数据
            hash256Source = Buffer.concat([hash256Source,plainText]);
        
            this.servSeq_++;
            nonce = GetNonce(hkdfRet.slice(0x2c), this.servSeq_);
            aesAad = Buffer.concat([Buffer.from([0x00, 0x00, 0x00, 0x00]) ,Int32ToBytes(this.servSeq_)]);
            aesAad = Buffer.concat([aesAad, packItems[3].head]);
            plainText  =  AesGcmDecrypt(aesKey,nonce,aesAad,packItems[3].data);
            console.log('解密服务器返回的第思部分数据:');
            console.log(Bytes2HexString(plainText));
            console.log('数据包全部解密完成,开始客户端组包')
    
            //客户端组包分2个包,1个是client finished包,一个是心跳包
            var hkdfClientFinish = HkdfExpand(secretKey,Buffer.from('client finished'), 32);
            var hashRet = Hash256Final(hash256Source);
            var hmacRet = HmacHash256(hkdfClientFinish, hashRet)
            nonce = GetNonce(hkdfRet.slice(0x20,0x2c), this.clientSeq_);
            aesAad = Buffer.concat([Buffer.from([0x00, 0x00, 0x00, 0x00]) ,Int32ToBytes(this.clientSeq_)]);
            aesAad = Buffer.concat([aesAad, packItems[3].head]);
            var data = Buffer.concat([Buffer.from([0x00, 0x00, 0x00, 0x23, 0x14, 0x00, 0x20]), hmacRet]);
            var clientData = AesGcmEncrypt(hkdfRet.slice(0,16), nonce, aesAad, data) //step 20
            console.log('组包client 数据:');
            console.log(Bytes2HexString(clientData));
            //构建client finish包
            var clientFinish = Buffer.concat([packItems[3].head,clientData]);
    
            var hkdfRet1 = HkdfExpand(secretKey, Buffer.concat([Buffer.from("expanded secret") ,hashRet]), 32)              //step 21
            hkdfRet1 = HkdfExpand(hkdfRet1, Buffer.concat([Buffer.from("application data key expansion") ,hashRet]) , 56) //step 22
            this.dataHkdf_ = hkdfRet1
            this.pskReqData_ = null;
            return Buffer.concat([clientFinish, this.BuildHeart()]);
         } catch (error) {
             
         }    
    }


    UnPack(data){
        try {
            this.servSeq_++;
            var aesKey = this.dataHkdf_.slice(0x10,0x20);
            var nonce = GetNonce(this.dataHkdf_.slice(0x2c), this.servSeq_);
            var aesAad = Buffer.concat([Buffer.from([0x00, 0x00, 0x00, 0x00]) ,Int32ToBytes(this.servSeq_)]);
            aesAad = Buffer.concat([aesAad, data.slice(0,5)]);
            return AesGcmDecrypt(aesKey,nonce,aesAad, data.slice(5));
        } catch (error) {
            console.log("解包失败" + error);
        }
    }

    
    BuildHeart(){
        return this.Pack(heartBeartData);
    }

    Pack(data){
        try {
            this.clientSeq_++;
            var nonce = GetNonce(this.dataHkdf_.slice(0x20,0x2c), this.clientSeq_);
            var aesAad = Buffer.concat([Buffer.from([0x00, 0x00, 0x00, 0x00]) ,Int32ToBytes(this.clientSeq_)]);
            aesAad = Buffer.concat([aesAad, Buffer.from([0x17, 0xf1, 0x03])]);
            aesAad = Buffer.concat([aesAad, Int16ToBytes(data.length+0x10)]);
    
            var packetData = AesGcmEncrypt(this.dataHkdf_.slice(0,16),nonce,aesAad,data);
            return Buffer.concat([aesAad.slice(8),packetData]);
        } catch (error) {
            console.log("打包" + error);
        }
     
    }  
    
    // 短链接会话票据
    UnpackNewSessionTicket(secretKey,hashRet) {
        try {
            var salt = Buffer.concat([Buffer.from('PSK_ACCESS'),hashRet]);
            var key1 = HkdfExpand(secretKey, salt, 32)

            var salt2 = Buffer.concat([Buffer.from('PSK_REFRESH'),hashRet]);
            return  HkdfExpand(secretKey, salt2, 32);
        } catch (error) {
            
        }
    }
}

module.exports = Tls1_3