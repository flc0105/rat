<template>
  <img
    :src="src"
    alt="Remote screen preview"
    class="screen-view-image"
    draggable="false"
  >
</template>

<script>
export default {
  name: 'FullJpegScreenRenderer',
  props: {
    src: {
      type: String,
      default: '',
    },
  },
}
</script>
