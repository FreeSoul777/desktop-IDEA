package prog.cipher;

import java.util.concurrent.*;

public class ThreadPool {

    private final ExecutorService executorService;

    public ThreadPool(int threadsNumber) {
        executorService = Executors.newFixedThreadPool(threadsNumber);
    }

    public void addTask(Cipher task) {
        executorService.submit(task);
    }

    public void waitAllTasks() {
        try {
            executorService.shutdown();
            executorService.awaitTermination(Long.MAX_VALUE, TimeUnit.NANOSECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void stop() {
        executorService.shutdownNow();
    }
}
