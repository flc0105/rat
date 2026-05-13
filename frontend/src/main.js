import {createApp} from 'vue'
import ElementPlus, {ElLoading, ElMessage, ElMessageBox, ElNotification,} from 'element-plus'

import 'element-plus/dist/index.css'
import App from './App.vue'

// 兼容旧代码里的 ElementPlus.ElMessage / ElementPlus.ElMessageBox
window.ElementPlus = ElementPlus
window.ElementPlus.ElMessage = ElMessage
window.ElementPlus.ElMessageBox = ElMessageBox
window.ElementPlus.ElNotification = ElNotification
window.ElementPlus.ElLoading = ElLoading

createApp(App)
    .use(ElementPlus)
    .mount('#app')