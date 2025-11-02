# ShareBird

Docker build:

```
docker volume create bd_cache
docker volume create gradle_cache

docker run --rm -it ^
  -e BUILDOZER_ALLOW_ROOT=1 ^
  -v "%cd%":/work ^
  -v bd_cache:/root/.buildozer ^
  -v gradle_cache:/root/.gradle ^
  -w /work ^
  kivy/buildozer ^
  buildozer android debug
```

```
docker run --rm -it --entrypoint /bin/bash ^
  -v "%cd%":/work ^
  -v bd_cache:/root/.buildozer ^
  -v gradle_cache:/root/.gradle ^
  -w /work ^
  kivy/buildozer -lc "yes | buildozer android debug"
```


To test:

```git clone https://github.com/deb-cod/ShareBird.git```


```pip install -r requirements.txt```


```python main.py```
