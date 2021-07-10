<p align="center">
  <img alt="Phaser logo" src="https://kerkour.com/imgs/phaser.svg" height="200" />
  <h1 align="center">Phaser</h1>
  <h3 align="center">High-performance attack surface mapper and vulnerability scanner</h3>
</p>



## What is this?

Phaser is a high-performance attack surface mapper and vulnerability scanner. Just point it to a target, and it will autimagically generate a report with everything it can finds, saving you hours of manual audit and pipping between different tools.


<!-- TODO: image architecture -->


Want to learn how to use Rust to hack the planet? Phaser was extracted from the chaptres 2, 3, and 4 of my book [Black Hat Rust](https://academy.kerkour.com/black-hat-rust?coupon=PHASER), where, among other things, we learn how to build a fast async scanner.

<div align="center">
  <a href="https://academy.kerkour.com/black-hat-rust?coupon=GITHUB" target="_blank" rel="noopener">
    <img alt="Black Hat Rust logo" src="https://kerkour.com/imgs/black_hat_rust_cover.svg" height="300" />
  </a>

  <h3>
    <a href="https://academy.kerkour.com/black-hat-rust?coupon=PHASER">Buy the book now!</a>
  </h3>
<div>


## Installation

### Using cargo

```shell
$ cargo install phaser
```


### Using Docker

```shel
$ docker pull gcr.io/skerkour/phaser
```


## Usage

```shell
# List modules
$ phaser modules
# Scan a target
$ phaser scan target.com
```


### With Docker

```shell
$ docker run -ti gcr.io/skerkour/phaser phaser scan target.com
```

## License
