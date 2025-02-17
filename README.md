# Common Jenkins Vulnerabilities Enumerator

This is an `intelliJIDE` plugin that look for some vulnerable patterns in `Jenkins` plugins.

## How to install

You need first to compile the plugin using the following command:

```sh
./gradlew buildPlugin
```

then you can find the `Jar` file in `build/libs/vulnerabilitiesJenkins-VERSION.jar`.

Then go to:

```sh
File > Settings... > Plugin > the on the top there is the gear icon > Install Plugin from Disk...
```

and choose the `Jar` file you compiled earlier, then Save.

You will see a new icon appear on the right side panel.
![img.png](images/img.png)

## How to use
Just open the plugin tab, and you shall get the potentially vulnerable patterns on a list, 
double click any element in the list and the concerned file on the concerned line will be opened.