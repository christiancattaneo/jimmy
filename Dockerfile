# jimmy in a container. Build is multi-stage so the runtime image carries only
# the compiled dist and production deps.
#
#   docker build -t jimmy .
#   docker run --rm -v "$PWD:/work" -w /work jimmy migrations lint --dir ./supabase/migrations
#   docker run --rm jimmy rls audit --db "$DATABASE_URL"

FROM node:20-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json tsup.config.ts ./
COPY src ./src
RUN npm run build

FROM node:20-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY --from=build /app/dist ./dist
COPY schema ./schema
# run as the built-in non-root node user
USER node
ENTRYPOINT ["node", "dist/cli/index.js"]
CMD ["--help"]
