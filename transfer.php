<?php
declare(strict_types=1);

use Transfer as Sandbox;
//接收参数校验并调用
if (!isset($_REQUEST['sign']) || !in_array($_REQUEST['sign'], ['getOpenId', 'sendRedPacket', 'checkTransfer'])) {
    throw new \Exception('请求标识参数错误');
}
$sign = $_REQUEST['sign'];
switch ($sign) {
    case 'getOpenId':
        $code = $_GET['code']??null;
        Sandbox::getInstance()->getOpenId($code);

        break;
    case 'sendRedPacket':
        Sandbox::getInstance()->checkHeaderSign($_SERVER);
        unset($_POST['sign']);
        if (!isset($_POST['openid'], $_POST['amount']) || $_POST['openid'] == 'undefined') {
            throw new \Exception('请求参数错误');
        }
        list($openId, $amount) = array_values($_POST);
        Sandbox::getInstance()->transfer($openId, $amount);

        break;
    case 'checkTransfer': //校验核对是否转账成功
        $batch = $_GET['batch']??null; //商家批次单号
        if (is_null($batch)) {
            throw new \Exception('商家批次单号参数错误');
        }
        Sandbox::getInstance()->checkTransfer($batch);

        break;
}

/**
 * RedPacket Class
 */
class Transfer{
    /**
     * @var $instance
     */
    private static $instance;

    /**
     * @var string $file
     */
    private $file;

    /**
     * @var $env
     */
    private $env;

    /**
     * @var mixed $apiClientCert
     */
    private $apiClientCert;

    /**
     * @var mixed $apiClientKey
     */
    private $apiClientKey;

    /**
     * @var string $logPath
     */
    private static $logPath;

    /**
     * @var array $log
     */
    private static $log=[];

    /**
     * @var $openId
     */
    private $openId;

    /**
     * @var $amount
     */
    private $amount;

    /**
     * @var $token
     */
    private $token;

    /**
     * Constructor
     */
    private function __construct()
    {
        $this->file = './.env';
        $this->setEnv();
        static::$logPath = sprintf('%s%s.log', $this->env['wx']['logDir'], date('Ymd'));
        //微信支付商户API证书
        $this->apiClientCert = $this->env['wx']['apiClientCert'];
        $this->apiClientKey = $this->env['wx']['apiClientKey'];
        //session设置
        session_set_cookie_params(7200);
        session_start();
    }

    /**
     * @return mixed
     */
    public static function getInstance()
    {
        if (!(static::$instance instanceof self)) {
            static::$instance = new self();
        }
        return static::$instance;
    }

    /**
     * 微信公众平台客户端获取用户openId
     *
     * @param $code
     * @return bool|string
     */
    public function getOpenId($code=null)
    {
        if (isset($_SESSION['openId']) && !is_null($_SESSION['openId'])) {
            return $this->responseCall(0, 'ok', ['openId' => $_SESSION['openId']]);
        }
        if (is_null($code)) {
            return $this->responseCall(10010, 'code不能为空');
        }
        $params = [
            'appid' => $this->env['wx']['appID'],
            'secret' => $this->env['wx']['appSecret'],
            'code' => $code,
            'grant_type' => 'authorization_code'
        ];
        $url = sprintf('%s%s?%s', $this->env['wx']['apiWxUrl'], 'sns/oauth2/access_token', http_build_query($params));

        $response = self::curlGet($url);
        if (!$response) {
            return $this->responseCall(10011, '获取openid失败');
        }

        $response = json_decode($response, true);
        if ($response['errcode'] != 0) {
            return $this->responseCall($response['errcode'], $response['errmsg']);
        }
        $_SESSION['openId'] = $response['openid'];

        return $this->responseCall(0, 'ok', ['openId' => $response['openid']]);
    }

    /**
     * 校验核对是否转账成功
     *
     * @param string|null $outBatchNo
     * @return false|string
     */
    /**
     * @param string|null $outBatchNo
     * @return null
     */
    public function checkTransfer(string $outBatchNo=null)
    {
        if (is_null($outBatchNo)) {
            return $this->responseCall(10020, '商家批次单号参数错误');
        }

        $url = sprintf('%s%s%s?need_query_detail=%s&detail_status=ALL', $this->env['wx']['payWxUrl'], 'v3/transfer/batches/out-batch-no/', $outBatchNo, true);
        $this->generateToken($url); //生成Authorization Token
        $response = self::curlGet($url);
        if (!$response) {
            return $this->responseCall(10021, '通过商家批次单号查询批次单失败');
        }

        $response = json_decode($response, true);
        if (isset($response['code'], $response['message'])) {
            return $this->responseCall(10022, $response['message']);
        }
        if (isset($response['transfer_detail_list'], $response['transfer_detail_list'][0]['detail_status'])
            && $response['transfer_detail_list'][0]['detail_status'] == 'SUCCESS') {
            return $this->responseCall(0, 'SUCCESS');
        }

        return $this->responseCall(10023, '转账失败');
    }

    /**
     * 发起商家转账API
     *
     * @param string $openId
     * @param string $amount
     * @return false|string
     */
    public function transfer(string $openId, string $amount)
    {
        list($this->openId, $this->amount) = func_get_args();
        static::$log['params'] = ['openid' => $openId, 'amount' => $amount];
        if (!$this->validateAmountRange()) {
            return $this->responseCall(10012, '商家转账到零钱额度不在规则范围');
        }

        //请求参数设置
        $fields = [
            'appid' => $this->env['wx']['appID'], //直连商户的appid
            'out_batch_no' => $this->generateOutTradeNo(), //商家批次单号
            'batch_name' => '扫码活动', //批次名称
            'batch_remark' => '扫码活动', //批次备注
            'total_amount' => intval(bcmul($this->amount, '100')), //转账总金额	单位 转为分
            'total_num' => 1, //转账总笔数
            'transfer_detail_list' => [
                [
                    'out_detail_no' => $this->generateOutTradeNo(), //商家明细单号
                    'transfer_amount' => intval(bcmul($this->amount, '100')), //转账金额  单位 转为分
                    'transfer_remark' => '扫码活动', //转账备注
                    'openid' =>  $this->openId //用户在直连商户应用下的用户标示 用户openid
                ]
            ]
        ];
        static::$log['request'] = json_encode($fields);

        //请求返回格式设置
        $url = sprintf('%s%s', $this->env['wx']['payWxUrl'], 'v3/transfer/batches');
        $this->generateToken($url, $fields, 'POST'); //生成Authorization Token
        $response = $this->curlRequest($url, json_encode($fields));
        static::$log['sendResp'] = $response;
        $response = json_decode($response,true);

        list($code, $data) = [10014, []];
        if (isset($response['batch_status']) && $response['batch_status'] == 'ACCEPTED') {
            $code = 0;
            $data = [
                'out_trade_no' => $response['out_batch_no'],
                'openid' => $this->openId,
                'total_amount' => $this->amount,
                'send_listid' => $response['batch_id'],
                'batch_id' => $response['batch_id'],
                'pay_time' => $response['create_time']
            ];
        }

        return $this->responseCall($code, $response['message']??'SUCCESS', $data);
    }

    /**
     * 生成Authorization Token
     *
     * @param string $url
     * @param array|null $body
     * @param string $method
     * @return void
     */
    private function generateToken(string $url, array $body=null, string $method='GET')
    {
        $timestamp = time(); //请求时间戳
        $url_parts = parse_url($url);
        $nonce = $timestamp.rand(10000, 99999); //请求随机串
        if ($method != 'GET') {
            $body = json_encode((object)$body); //请求报文主体
        }
        $stream_opts = [
            "ssl" => [
                "verify_peer"=>false,
                "verify_peer_name"=>false,
            ]
        ];
        $mch_private_key = file_get_contents($this->apiClientKey,false, stream_context_create($stream_opts));//密钥
        $canonical_url = ($url_parts['path'] . (!empty($url_parts['query']) ? "?${url_parts['query']}" : ""));
        $message = $method."\n".
            $canonical_url."\n".
            $timestamp."\n".
            $nonce."\n";
        if (!is_null($body)) {
            $message .= $body;
        }
        $message .= "\n";
        openssl_sign($message, $raw_sign, $mch_private_key, 'sha256WithRSAEncryption');
        $sign = base64_encode($raw_sign);

        $this->token = sprintf('mchid="%s",nonce_str="%s",timestamp="%d",serial_no="%s",signature="%s"',
            $this->env['wx']['merchantId'], $nonce, $timestamp, $this->env['wx']['serialNo'], $sign);
    }

    /**
     * 发红包请求
     *
     * @param string $openId
     * @param string $amount
     * @return false|string
     */
    public function sendRedPacket(string $openId, string $amount)
    {
        list($this->openId, $this->amount) = func_get_args();
        static::$log['params'] = ['openid' => $openId, 'amount' => $amount];
        if (!$this->validateAmountRange()) {
            return $this->responseCall(10012, '发放现金红包额度不在规则范围');
        }
        //生成现金红包参数调用
        $response = $this->createJsBizPackage();
        if (!$response) {
            return $this->responseCall(10013, '调用微信发放红包接口失败');
        }

        $data = [];
        if ($response['result_code'] == 'SUCCESS') {
            $data = [
                'out_trade_no' => $response['mch_billno'],
                'openid' => $response['re_openid'],
                'total_amount' => $response['total_amount'],
                'send_listid' => $response['send_listid'],
                'pay_time' => time()
            ];
        }

        $codeConvert = ['SUCCESS' => 0, 'FAIL' => 10014];
        return $this->responseCall($codeConvert[$response['result_code']], $response['return_msg'], $data);
    }

    /**
     * 校验签名认证
     *
     * @param array $header
     * @return false|string|void
     */
    public function checkHeaderSign(array $header)
    {
        if (!isset($header['HTTP_OPENID'], $header['HTTP_AMOUNT'], $header['HTTP_TIMESTAMP'], $header['HTTP_SIGN'])) {
            return $this->responseCall(500, '检验认证参数错误');
        }
        list($openid, $amount, $timestamp, $sign) = [
            $header['HTTP_OPENID'],
            $header['HTTP_AMOUNT'],
            $header['HTTP_TIMESTAMP'],
            $header['HTTP_SIGN']
        ];
        // 校验Header参数
        if (empty($openid) || empty($amount) || empty($timestamp) || empty($sign)) {
            return $this->responseCall(500, '检验认证参数错误');
        }
        // 校验时间戳参数
        if ((time() - $timestamp) >= 2) {
            return $this->responseCall(500, '时间戳参数错误');
        }
        // 校验发放现金红包范围
        $this->amount = $amount;
        if (!$this->validateAmountRange()) {
            return $this->responseCall(10012, '发放现金红包额度不在规则范围');
        }

        // 认证参数按照指定规则校验认证
        $params = [
            'appid' => $this->env['wx']['appID'],
            'openid' => $openid,
            'amount' => $amount,
            'timestamp' => $timestamp
        ];
        ksort($params, SORT_STRING);
        $signStr = strtoupper(md5(self::formatQueryParamMap($params)));
        if ($signStr != $sign) {
            return $this->responseCall(500, '检验认证失败');
        }
    }

    /**
     * 校验发放现金红包范围
     *
     * @return bool
     */
    private function validateAmountRange():bool
    {
        return !empty($this->amount) && floatval($this->amount) >= 0.1 && floatval($this->amount) <= 100;
    }

    /**
     * 生成现金红包参数调用
     *
     * @return false|mixed|string
     */
    private function createJsBizPackage()
    {
        if (!$this->validateAmountRange()) {
            return $this->responseCall(10012, '发放现金红包额度不在规则范围');
        }
        //请求参数设置
        $fields = [
            'wxappid' => $this->env['wx']['appID'], //公众账号appid
            'send_name' => $this->env['wx']['merchant'], //商户名称
            'mch_id' => $this->env['wx']['merchantId'], //商户号
            'nonce_str' => self::createNonceStr(), //随机字符串
            're_openid' => $this->openId, //用户openid
            'mch_billno' => $this->generateOutTradeNo(), //商户订单号
            'client_ip' => $_SERVER['remote_addr']??'127.0.0.1', //ip地址
            'total_amount' => intval(bcmul($this->amount, '100')), //单位 转为分
            'total_num' => 1, //红包发放总人数
            'wishing' => '扫码活动', //红包祝福语
            'act_name' => '扫码活动', //活动名称
            'remark' => '扫码活动', //备注信息, 如为中文注意转为UTF8编码
            'scene_id' => 'PRODUCT_1' //发放红包使用场景, 红包金额大于200或者小于1元时必传
        ];
        $fields['sign'] = self::generateSignature($fields, $this->env['wx']['payKey']); //签名
        static::$log['request'] = json_encode($fields);

        //请求返回格式设置
        $url = sprintf('%s%s', $this->env['wx']['payWxUrl'], 'mmpaymkttransfers/sendredpack');
        $responseXml = $this->curlPost($url, self::arrayToXml($fields));
        $response = simplexml_load_string($responseXml, 'SimpleXMLElement', LIBXML_NOCDATA);
        $response = json_encode($response);
        static::$log['sendResp'] = $response;
        $response = json_decode($response,true);

        return $response;
    }

    /**
     * 随机字符串
     *
     * @param int $length
     * @return string
     */
    private static function createNonceStr(int $length = 16):string
    {
        $str = '';
        $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        for ($i = 0; $i < $length; $i++) {
            $str .= substr($chars, mt_rand(0, strlen($chars) - 1), 1);
        }

        return $str;
    }

    /**
     * 生成商户订单号
     *
     * @return string
     */
    private function generateOutTradeNo():string
    {
        return sprintf('%s%s%s', $this->env['wx']['merchantId'], date('YmdHis'), rand(1000, 9999), date('His'));
    }

    /**
     * 生成签名
     *
     * @param array $params
     * @param string $key
     * @return string
     */
    private static function generateSignature(array $params, string $key):string
    {
        ksort($params, SORT_STRING);
        $signParamString = self::formatQueryParamMap($params, false);
        $signStr = strtoupper(md5($signParamString."&key=".$key));

        return $signStr;
    }

    /**
     * 数据格式映射
     *
     * @param array $paramMap
     * @param bool $urlEncode
     * @return false|string
     */
    private static function formatQueryParamMap(array $paramMap, bool $urlEncode = false)
    {
        $buff = "";
        ksort($paramMap);
        foreach ($paramMap as $k => $v) {
            if (null != $v && "null" != $v) {
                if ($urlEncode) {
                    $v = urlencode($v);
                }
                $buff .= $k . "=" . $v . "&";
            }
        }
        $reqParam = '';
        if (strlen($buff) > 0) {
            $reqParam = substr($buff, 0, strlen($buff) - 1);
        }

        return $reqParam;
    }

    /**
     * 数组转xml
     *
     * @param array $arr
     * @return string
     */
    private static function arrayToXml(array $arr):string
    {
        $xml = "<xml>";
        foreach ($arr as $key => $val) {
            if (is_numeric($val)) {
                $xml .= "<" . $key . ">" . $val . "</" . $key . ">";
            } else {
                $xml .= "<" . $key . "><![CDATA[" . $val . "]]></" . $key . ">";
            }
        }
        $xml .= "</xml>";

        return $xml;
    }

    /**
     * 获取环境变量配置
     *
     * @return void
     * @throws Exception
     */
    private function setEnv()
    {
        if (is_file($this->file)) {
            $this->env = file_get_contents($this->file);
            $this->env = preg_replace('/\/\*[\S\s]*?\*\//', '' , $this->env);
            $this->env = preg_replace('/\/\/[^"]*\n/', '', $this->env);
            $this->env = json_decode($this->env, true);
        }

        if(is_null($this->env)){
            throw new \Exception('环境变量解析失败');
        }
    }

    /**
     * 日志记录目录
     *
     * @return void
     */
    private static function loggerCall()
    {
        $logText = sprintf('【%s】扫商品码领现金记录，数据记录结果【%s】%s', date('Y-m-d H:i:s'), json_encode(static::$log), PHP_EOL.PHP_EOL);
        $file = fopen(static::$logPath, 'a');
        if ($file && fwrite($file, $logText)) {
            fclose($file);
        }
    }

    /**
     * 设置返回数据格式
     *
     * @param int $code
     * @param string $msg
     * @param array $data
     * @return void
     */
    private function responseCall(int $code = 0, string $msg = 'ok', array $data = [])
    {
        header('Content-Type: application/json; charset=utf-8');
        header('Access-Control-Allow-Origin:*');
        header('Access-Control-Allow-Credentials: true');
        header('Access-Control-Allow-Methods:GET, POST, PUT, DELETE, OPTIONS, PATCH');

        $body = [
            'code' => $code,
            'msg' => $msg,
            'data' => $data
        ];
        $responseBody = json_encode($body, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        static::$log['response'] = $responseBody;
        static::loggerCall();
        echo $responseBody;exit();
    }

    /**
     * Curl Get请求封装
     *
     * @param string $url
     * @return bool|string
     */
    private function curlGet(string $url)
    {
        $curl = curl_init();
        curl_setopt($curl, CURLOPT_URL, $url);
        curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, FALSE);
        curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, FALSE);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($curl, CURLOPT_TIMEOUT, 30);
        //添加请求头
        $headers = [
            'Authorization:WECHATPAY2-SHA256-RSA2048 '.$this->token,
            'Accept: application/json',
            'Content-Type: application/json; charset=utf-8',
            'User-Agent:Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36',
        ];
        curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);
        $data = curl_exec($curl);
        curl_close($curl);

        return $data;
    }

    /**
     * Curl Post请求封装
     *
     * @param $url
     * @param $postData
     * @return bool|string
     */
    private function curlPost($url, $postData)
    {
        if (is_array($postData)) {
            $postData = http_build_query($postData);
        }
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $postData);
        curl_setopt($ch, CURLOPT_TIMEOUT, 30); //设置cURL允许执行的最长秒数
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);

        //cert 与 key 分别属于两个.pem文件
        //默认格式为PEM，可以注释
        curl_setopt($ch,CURLOPT_SSLCERTTYPE, 'PEM');
        curl_setopt($ch,CURLOPT_SSLCERT, $this->apiClientCert);
        //默认格式为PEM，可以注释
        curl_setopt($ch,CURLOPT_SSLKEYTYPE, 'PEM');
        curl_setopt($ch,CURLOPT_SSLKEY, $this->apiClientKey);
        $data = curl_exec($ch);
        curl_close($ch);

        return $data;
    }

    /**
     * Curl Request请求封装
     *
     * @param $url
     * @param $data
     * @return bool|string
     */
    private function curlRequest($url, $data)
    {
        $curl = curl_init();
        curl_setopt($curl, CURLOPT_URL, (string)$url);
        curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, FALSE);
        curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, FALSE);
        curl_setopt($curl, CURLOPT_POST, 1);
        curl_setopt($curl, CURLOPT_POSTFIELDS, $data);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
        //添加请求头
        $headers = [
            'Authorization:WECHATPAY2-SHA256-RSA2048 '.$this->token,
            'Accept: application/json',
            'Content-Type: application/json; charset=utf-8',
            'User-Agent:Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36',
        ];
        curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);
        $output = curl_exec($curl);
        curl_close($curl);

        return $output;
    }
}