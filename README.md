<picture width="512" align="right">
 <source media="(prefers-color-scheme: dark)" srcset="./assets/befake-white.png">
 <img src="./assets/befake-black.png">
</picture>


A cool tool for collecting all your friends' photos from BeReal (including RealMojis) without taking any screenshots, opening the app, annoying analytics and much much more!

> [!NOTE]
> This is a fork of [notmarek/BeFake](https://github.com/notmarek/BeFake), which unfortunately has been cease-and-desisted by BeReal.
> I maintain this fork for personal use, so I cannot promise that features besides _login_ and _friends feed_ will work. PRs are welcome either way!

> [!WARNING]
> Because this is primarily for personal use, there _will_ be breaking changes without warning. Make sure to pin the version you are using!

## Install
```bash
pip install git+https://github.com/NicoWeio/BeFake
```

## Usage
```bash
befake [OPTIONS] COMMAND [ARGS]...
```


## Docker
```bash
# NOTE: This specific command is untested.
docker run -v "{HOST_DATA_DIRECTORY}:/data" -v "{TOKEN}:/data/token.txt" ghcr.io/nicoweio/befake:latest {command}
```


## Related projects
- web clients
  - https://github.com/rvaidun/befake
    - web client
    - most popular at >200 ⭐
    - using VueJS
  - https://github.com/s-alad/toofake
    - web client
    - public deployment available: https://toofake.lol/
  - https://github.com/chemokita13/BeRealGate
    - web client
    - public deployment available: https://berealgate.vercel.app/
    - using NextJS and TailwindCSS
- CLI clients / libraries
  - https://github.com/Smart123s/BeFake
    - forked from the original _notmarek/BeFake_ (like this repo)
    - no longer in active development; cherry-picking commits from this repo instead
    - CLI client
    - using Python
- API wrappers
  - https://github.com/chemokita13/beReal-api
    - public deployment available: https://berealapi.fly.dev/
    - using NestJS
- other
  - https://github.com/theOneAndOnlyOne/BeReel
    - tool to create timelapses akin to BeReal's Recap feature
  - https://shomil.me/bereal/
    - article about reverse engineering BeReal
- archived / down
  - https://github.com/notmarek/BeFake/
    - the original project
    - hit by cease-and-desist 📜
  - https://github.com/ArtrenH/BeFake-Dashboard
    - depends on the original _notmarek/BeFake_


## Developement
```bash
  python -m venv .venv // create a venv (optional)
  source .venv/bin/activate

  pip install -r requirements.txt
  python befake.py
```

have fun
