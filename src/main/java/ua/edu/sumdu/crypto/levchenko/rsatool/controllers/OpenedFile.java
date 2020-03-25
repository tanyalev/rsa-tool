package ua.edu.sumdu.crypto.levchenko.rsatool.controllers;

class OpenedFile {
    private final String name;
    private final String data;

    public OpenedFile() {
        this("", "");
    }

    public OpenedFile(String name, String data) {
        this.name = name;
        this.data = data;
    }

    public String getName() {
        return name;
    }

    public String getData() {
        return data;
    }

    public boolean isEmpty() {
        return (name.isEmpty() || data.isEmpty()) || (name.isBlank() || data.isBlank());
    }
}
