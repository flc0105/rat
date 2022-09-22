axios.interceptors.response.use(res => {
    if (res.status === 200) {
        return res.data
    }
})

// 接收上线提醒
var socket = io.connect(STATIC_URL)
socket.on('connect', function () {
    console.log('connected')
})
socket.on('message', function (data) {
    Push.create('上线提醒', {
        body: data,
        timeout: 10000,
        onClick: function () {
            window.focus()
            this.close()
        }
    })
})

const app = Vue.createApp({
    data() {
        return {
            // 客户端列表
            connections: [],
            // 命令
            command: '',
            // 目标客户端序号
            target: 0,
            // 命令记录
            result: '',
            // 目标当前工作目录的路径
            cwd: '',
            old_cwd: '',
            // 等待返回结果
            wait: false
        }
    },
    methods: {
        // 获取客户端列表
        list() {
            axios.post(API_URL + '/list')
                .then((res) => {
                    this.connections = res
                })
                .catch((err) => {
                    alert(err.message)
                })
        },
        // 获取客户端当前工作目录的路径
        getcwd() {
            axios.post(API_URL + '/getcwd', { 'target': this.target })
                .then((res) => {
                    this.cwd = res
                    this.old_cwd = res
                })
                .catch((err) => {
                    alert(err.message)
                })
        },
        // 向客户端发送命令
        execute() {
            if (this.command.trim().length == 0) {
                return
            }
            this.wait = true
            axios.post(API_URL + '/execute', { 'target': this.target, 'command': this.command })
                .then((res) => {
                    result = res[0]
                    this.cwd = res[1]
                    this.result += (this.old_cwd == null ? '' : this.old_cwd) + '> ' + this.command + '\n' + result + '\n'
                    this.old_cwd = this.cwd
                    this.command = ''
                    this.wait = false
                    
                })
                .catch((err) => {
                    alert(err.message)
                    this.wait = false
                })
        },
    },
    mounted() {
        // 获取客户端列表
        this.list()
    },
    updated() {
        // 滚动条始终在底部
        var result = document.getElementById('result')
        result.scrollTop = result.scrollHeight
        // 保持命令输入框获得焦点
        document.getElementById('command').focus()
    }
})

app.mount('body')
