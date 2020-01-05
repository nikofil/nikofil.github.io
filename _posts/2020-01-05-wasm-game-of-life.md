---
title: "WASM Game of Life"
categories: Rust Coding
tags: rust wasm
toc: false
---

This is an implementation of Game Of Life in Rust compiled to WASM based on [the Rust and WASM book](https://rustwasm.github.io/docs/book/). This means it's Rust, running on the browser, faster than JS could ever hope to be! (if I didn't mess it up)  
You can use the controls on the bottom to start / stop / reset the state and control the speed. You can also click on boxes to toggle them, or drag over them to change a bunch at a time.  
Code is hosted on [Github](https://github.com/nikofil/wasm-gameoflife).

<div style="text-align: center">
  <div>
      <canvas id="gol-canvas"></canvas>
  </div>
  <table style="text-align: center; display: table">
    <tr>
      <td>
        <input type="button" id="pause" value="Play / Stop" />
      </td><td>
        <input type="button" id="step" value="Step" />
      </td><td>
        <input type="button" id="clear" value="Clear" />
      </td><td>
        <input type="button" id="random" value="Random" />
      </td><td>
        <input type="button" id="default" value="Default" />
      </td><td>
        <span style="position:relative; bottom: 0.75em">Speed</span>&nbsp;&nbsp;
        <input type="range" style="width: 100px" min="0" max="61" value="10" id="range" />
      </td><td>
        FPS: <span id="fps"></span>
      </td>
    </tr>
  </table>
</div>
<script src="/assets/js/gameoflife.js"></script>
