#include <stdio.h>

#define INF 999

int main() {
    int n, source;
    int cost[10][10];
    int dist[10];

    printf("Enter number of nodes: ");
    scanf("%d", &n);

    printf("Enter cost matrix (use 999 for no link):\n");

    for (int i = 0; i < n; i++) {
        for (int j = 0; j < n; j++) {
            scanf("%d", &cost[i][j]);
        }
    }

    printf("Enter source node: ");
    scanf("%d", &source);

    // Initialize distances
    for (int i = 0; i < n; i++) {
        dist[i] = cost[source][i];
    }

    // Distance from source to itself is 0
    dist[source] = 0;

    // Bellman-Ford: relax all edges n-1 times
    for (int k = 0; k < n - 1; k++) {

        for (int i = 0; i < n; i++) {

            for (int j = 0; j < n; j++) {

                if (dist[i] != INF &&
                    cost[i][j] != INF &&
                    dist[i] + cost[i][j] < dist[j]) {

                    dist[j] = dist[i] + cost[i][j];
                }
            }
        }
    }

    printf("\nDestination\tCost\n");

    for (int i = 0; i < n; i++) {
        if (dist[i] == INF)
            printf("Node %d\t\tINF\n", i);
        else
            printf("Node %d\t\t%d\n", i, dist[i]);
    }

    return 0;
}

