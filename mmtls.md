# MMTLS js 源码实现，可以翻译成其他语言
```js
const tls13 = require('./tls1.3')
const net = require('net');

//TCP 长连接的包可能分很多次过来，需要缓存起来，并且判断是否接收完一个包
var recvBuffer = Buffer.alloc(0);
var handshake = 0;
//mmtls 协议
var tlsClient = new tls13();
//TCP 长连接， 用来和微信服务器建立长连接
var tcpClient = new net.Socket();

function TestUnPack(offset) {
    //长度必须大于5个字节
    if(offset == null){
        offset = 0;
    }
    if(recvBuffer.length < (5 + offset)){
        return null;
    }
    var len = recvBuffer.readInt16BE(offset+3);
    if(recvBuffer.length < (5 +len+offset)){
        return null;
    }
    return {"offset":5+offset,"len":len};
}



function HandleServerFinis(){
    //目前有4个节点，需要判断4个节点是否都已经读取完了
   var offset = 0;
   for(var i=0;i<4;i++){
      var unPackInfo = TestUnPack(offset);
      if(unPackInfo == null){
        return;
      }
      offset = unPackInfo.offset + unPackInfo.len;
   }

   var serverFinishData = recvBuffer.slice(0,offset);
   recvBuffer = recvBuffer.slice(offset);
   var clientFinish = tlsClient.HandleServerFinish(serverFinishData);
   tcpClient.write(clientFinish);
   handshake=1;

   //测试，发送心跳包，1分钟发送一次
   setInterval(function(){
       tcpClient.write(tlsClient.BuildHeart());   
    }, 60*1000);
}


function HandleUnPack(){
    var packDataInfo = TestUnPack(0);
    if(null == packDataInfo){
        return;
    }

    var packData = recvBuffer.slice(0,packDataInfo.offset+packDataInfo.len);
    recvBuffer = recvBuffer.slice(packDataInfo.offset+packDataInfo.len);
    //解密一个数据包
    var unpackData =tlsClient.UnPack(packData);  
    console.log(unpackData);

    //继续处理下一个包
    HandleUnPack();
}


//接收长连接发来的数据
function HandleRecvData(data){
    //判断是否已经握手完成了
    recvBuffer = Buffer.concat([recvBuffer, data]);
    if(handshake == 0){
        //这是一个client finis 包
        HandleServerFinis();
    } else{
      //已经握手完成了，那就直接解包
      HandleUnPack();
    }
  }


tcpClient.connect(443,"long.weixin.qq.com", ()=>{
    //连接成功
    //第一步 发送握手包
    tcpClient.write(tlsClient.BuildPskRequest());
});


tcpClient.on('data',(data)=>{
    HandleRecvData(data);
});


```