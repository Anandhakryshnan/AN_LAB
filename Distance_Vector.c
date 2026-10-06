#include <stdio.h>

#define INF 999

void distanceVector(int cost[][10], int n)
{
    int dist[10][10];
    int i, j, k;

    // Initialize distance table
    for (i = 0; i < n; i++)
    {
        for (j = 0; j < n; j++)
        {
            dist[i][j] = cost[i][j];
        }
    }

    // Bellman-Ford relaxation
    for (k = 0; k < n - 1; k++)
    {
        for (i = 0; i < n; i++)
        {
            for (j = 0; j < n; j++)
            {
                if (dist[i][k] + dist[k][j] < dist[i][j])
                {
                    dist[i][j] = dist[i][k] + dist[k][j];
                }
            }
        }
    }

    // Display routing tables
    for (i = 0; i < n; i++)
    {
        printf("\nRouting table for Router %d:\n", i + 1);
        printf("Destination\tCost\n");

        for (j = 0; j < n; j++)
        {
            printf("%d\t\t%d\n", j + 1, dist[i][j]);
        }
    }
}

int main()
{
    int cost[10][10];
    int n, i, j;

    printf("Enter the number of routers: ");
    scanf("%d", &n);

    printf("Enter the cost matrix:\n");
    printf("(Enter %d for infinity)\n", INF);

    for (i = 0; i < n; i++)
    {
        for (j = 0; j < n; j++)
        {
            scanf("%d", &cost[i][j]);
        }
    }

    distanceVector(cost, n);

    return 0;
}

