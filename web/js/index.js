axios.interceptors.response.use(res => {
    if (res.status === 200) {
        return res.data
    }
})

var url = 'http://localhost:8888'

const app = Vue.createApp({
    data() {
        return {
            // 客户端列表
            connections: {},
            // 命令
            command: '',
            // 目标客户端序号
            target: 0,
            // 命令记录
            result: '',
            // 目标当前工作目录的路径
            cwd: '',
            old_cwd: ''
        }
    },
    methods: {
        // 获取客户端列表
        list() {
            axios.post(url + '/list')
                .then((res) => {
                    this.connections = res
                })
                .catch((err) => {
                    alert(err.message)
                })
        },
        // 获取客户端当前工作目录的路径
        getcwd() {
            axios.post(url + '/getcwd', { 'target': this.target })
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
            var input = document.getElementById('command')
            var btn = document.getElementById('execute')
            input.setAttribute('disabled', 'disabled')
            btn.setAttribute('disabled', 'disabled')
            axios.post(url + '/execute', { 'target': this.target, 'command': this.command })
                .then((res) => {
                    result = res[0]
                    this.cwd = res[1]
                    this.result += (this.old_cwd == null ? '' : this.old_cwd) + '> ' + this.command + '\n' + result + '\n'
                    this.old_cwd = this.cwd
                    this.command = ''
                    input.removeAttribute('disabled')
                    btn.removeAttribute('disabled')
                })
                .catch((err) => {
                    alert(err.message)
                })

        },
    },
    mounted() {
        this.list()
    },
    updated() {
        var result = document.getElementById('result')
        result.scrollTop = result.scrollHeight
    }
})

app.mount('body')
